
rule Backdoor_Win64_Androm_KK_MTB{
	meta:
		description = "Backdoor:Win64/Androm.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 c9 ba 00 00 02 00 41 b8 00 30 00 00 44 8d 49 40 ff 15 8b 32 1b 00 } //1
		$a_03_1 = {48 8d 0d cb 86 20 00 45 33 c9 45 33 c0 ff 15 ?? ?? ?? ?? 48 c7 44 24 28 00 00 00 00 45 33 c9 48 8b c8 c7 44 24 20 00 00 20 80 45 33 c0 48 8b d3 48 8b f8 ff 15 } //1
		$a_01_2 = {52 65 6c 65 61 73 65 5c 4d 46 43 4c 69 62 72 61 72 79 33 2e 70 64 62 } //1 Release\MFCLibrary3.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}