
rule Trojan_Win64_Strab_ASB_MTB{
	meta:
		description = "Trojan:Win64/Strab.ASB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 48 8d 4d a0 48 89 45 04 89 45 0c 48 8d 05 ?? ?? ?? ?? 0f 11 45 b4 0f 11 45 a4 48 89 45 b0 48 8d 85 f0 00 00 00 0f 11 45 c4 48 89 45 b8 0f 11 45 d4 } //3
		$a_03_1 = {48 8d 0d c3 c2 01 00 ff 15 ?? ?? ?? ?? 33 c9 ff 15 } //2
		$a_01_2 = {5c 64 61 6e 69 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 6e 6f 63 6f 6e 73 6f 6c 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 6e 6f 63 6f 6e 73 6f 6c 65 2e 70 64 62 } //1 \danie\source\repos\noconsole\x64\Release\noconsole.pdb
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}