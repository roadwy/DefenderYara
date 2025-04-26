
rule Trojan_Win32_TurtleSimple_A_dha{
	meta:
		description = "Trojan:Win32/TurtleSimple.A!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7c 53 7c 53 7c 49 7c 20 7c 28 7c 53 7c 69 7c 6d 7c 70 7c 6c 7c 65 7c 20 7c 53 7c 68 7c 65 7c 6c 7c 6c 7c 63 7c 6f 7c 64 7c 65 7c 20 7c 49 7c 6e 7c 6a 7c 65 7c 63 7c 74 7c 6f 7c 72 7c 29 7c } //1 |S|S|I| |(|S|i|m|p|l|e| |S|h|e|l|l|c|o|d|e| |I|n|j|e|c|t|o|r|)|
		$a_01_1 = {52 65 61 64 79 3f 20 47 6f 21 } //1 Ready? Go!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}