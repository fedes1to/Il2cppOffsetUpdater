using System.Text.RegularExpressions;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm64;
using PatternFinder;

const Arm64DisassembleMode disassembleMode = Arm64DisassembleMode.Arm; // if this doesnt work try LittleEndian

int itemSectionStart = 0;

if (!File.Exists("offsets.txt")) {
    Console.WriteLine("Please provide a valid offsets.txt in the folder of the program");
    Console.ReadKey();
    return;
}

if (!File.Exists("old.so")) {
    Console.WriteLine("Please provide a valid old.so file in the folder of the program");
    Console.ReadKey();
    return;
}

if (!File.Exists("new.so")) {
    Console.WriteLine("Please provide a valid new.so file in the folder of the program");
    Console.ReadKey();
    return;
}

Console.WriteLine("Please enter a valid signature length, we recommend using at least 64");
int sigLength = Convert.ToInt32(Console.ReadLine()); // please put at LEAST 48 or it wont find it

string[] offsetStrings = File.ReadAllLines("offsets.txt");

List<string> patterns = new List<string>();

FileStream oldFile = new FileStream("old.so", FileMode.Open);
BinaryReader oldReader = new BinaryReader(oldFile);
int oldLength = Convert.ToInt32(oldFile.Length);
oldReader.BaseStream.Position = itemSectionStart;
byte[] oldBytes = oldReader.ReadBytes(oldLength);

FileStream newFile = new FileStream("new.so", FileMode.Open);
BinaryReader newReader = new BinaryReader(newFile);
int newLength = Convert.ToInt32(newFile.Length);
newReader.BaseStream.Position = itemSectionStart;
byte[] newBytes = newReader.ReadBytes(newLength);

File.Delete("out.txt");

foreach (string offsetStr in offsetStrings) {
    int offset = Convert.ToInt32(offsetStr, 16);

    // we will attempt to only disassemble the bytes from the target offset
    byte[] targetBytes = oldBytes[offset..(offset + sigLength)];

    string pattern = string.Empty;

    using (CapstoneArm64Disassembler disassembler = CapstoneDisassembler.CreateArm64Disassembler(disassembleMode)) {
        disassembler.EnableInstructionDetails = false; // if this doesnt work try true
        disassembler.DisassembleSyntax = DisassembleSyntax.Intel;
        disassembler.EnableSkipDataMode = true;

        Arm64Instruction[] instructions = disassembler.Disassemble(targetBytes);

        foreach (Arm64Instruction instruction in instructions) {
            ulong hexValue = 0;
            Match match = Regex.Match(instruction.Operand, @".*(0x[0-9a-fA-F]+).*", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                string key = match.Groups[1].Value;

                hexValue = (ulong)new System.ComponentModel.UInt64Converter().ConvertFromString(key);
            }
            if (hexValue <= 256) {
                pattern += Convert.ToHexString(instruction.Bytes);
            } else {
                for (int i = 0; i < 4; i++) {
                    pattern += "??";
                }
            }
        }
        pattern = pattern.TrimEnd('?');
    }
    if (pattern.Length < sigLength) {
        pattern = string.Empty;
        byte[] newTargetBytes = oldBytes[offset..(offset + sigLength * 2)];
        using (CapstoneArm64Disassembler disassembler = CapstoneDisassembler.CreateArm64Disassembler(disassembleMode)) {
            disassembler.EnableInstructionDetails = false; // if this doesnt work try true
            disassembler.DisassembleSyntax = DisassembleSyntax.Intel;
            disassembler.EnableSkipDataMode = true;

            Arm64Instruction[] instructions = disassembler.Disassemble(newTargetBytes);

            foreach (Arm64Instruction instruction in instructions) {
                ulong hexValue = 0;
                Match match = Regex.Match(instruction.Operand, @".*(0x[0-9a-fA-F]+).*", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    string key = match.Groups[1].Value;

                    hexValue = (ulong)new System.ComponentModel.UInt64Converter().ConvertFromString(key);
                }
                if (hexValue <= 256) {
                    pattern += Convert.ToHexString(instruction.Bytes);
                } else {
                    for (int i = 0; i < 4; i++) {
                        pattern += "??";
                    }
                }
            }
            pattern = pattern.TrimEnd('?');
        }
    }
    pattern = Regex.Replace(pattern, ".{2}", "$0 ");
    patterns.Add(pattern);
}

List<long> newOffsets = new List<long>();

int index = 0;
foreach (string pattern in patterns) {
    long foundOffset;
    var transformPattern = Pattern.Transform(pattern);
    if(Pattern.Find(newBytes, transformPattern, out foundOffset))
        Console.WriteLine($"Found pattern at 0x{foundOffset.ToString("X")}! Old offset was {offsetStrings[index]}");
    else
        Console.WriteLine("Failed to find offset at " + offsetStrings[index]);
    newOffsets.Add(foundOffset);
    index++;
}

using (StreamWriter sw = new StreamWriter("out.txt"))
{
    for (int i = 0; i < patterns.Count; i++) {
        if (newOffsets[i] > 0)
            sw.WriteLine("Old offset = " + offsetStrings[i] + ", new offset = 0x" + newOffsets[i].ToString("X") + "\nPattern = " + patterns[i] + "\n");
        else
            sw.WriteLine("Failed to find offset at " + offsetStrings[i] + "\n");
    }
}

Console.WriteLine("Done!, remember to test other sigLength(s).");