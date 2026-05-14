
rule Trojan_Win64_ShellcodeRunner_AHK_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {62 79 70 61 73 73 2d 61 67 65 6e 74 5f 32 5c 77 6f 72 6b 73 70 61 63 65 5c 73 73 76 61 67 65 6e 74 5f [0-1c] 5f 78 6f 72 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 64 65 70 6c 6f 79 } //30
		$a_01_1 = {78 6f 72 5f 64 61 74 61 2e 64 61 74 } //20 xor_data.dat
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}