
rule Backdoor_Win32_Androm_GJO_MTB{
	meta:
		description = "Backdoor:Win32/Androm.GJO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 20 b8 ?? ?? ?? ?? 81 75 ?? ff 00 ff 00 83 f8 07 ?? ?? 29 d2 83 6d fc 77 66 ba 61 00 3b 55 f8 ?? ?? c7 45 ?? 40 00 00 00 b9 ?? ?? ?? ?? 83 6d f4 04 83 f9 00 ?? ?? 8b 45 ec 8d 45 f4 81 f8 aa 09 00 00 } //10
		$a_80_1 = {6d 61 78 20 45 64 69 74 69 6f 6e 2e 65 78 65 } //max Edition.exe  1
		$a_01_2 = {2e 72 6f 70 66 } //1 .ropf
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}