
rule Trojan_Win64_KillAV_BSB_MTB{
	meta:
		description = "Trojan:Win64/KillAV.BSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 04 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 33 d2 e9 f2 fd ff ff cc cc e9 17 4d 00 00 ?? ?? ?? 48 8b c4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 } //20
		$a_01_1 = {89 05 a0 1b 02 00 e8 cb 4c 00 00 33 c9 48 89 05 9a 1b 02 00 e8 15 52 } //5
		$a_01_2 = {c1 fa 06 4c 89 34 03 48 8b c5 83 e0 3f 48 8d 0c c0 49 8b 04 d0 } //5
		$a_81_3 = {72 65 6e 61 6d 65 64 2c 20 6d 73 6d 70 65 6e 67 2e 65 78 65 2c 20 6e 69 73 73 72 76 2e 65 78 65 2c 20 61 6e 64 20 6d 70 63 6d 64 72 75 6e 2e 65 78 65 20 77 65 72 65 20 61 6c 6c 20 72 65 6e 61 6d 65 64 } //15 renamed, msmpeng.exe, nissrv.exe, and mpcmdrun.exe were all renamed
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_81_3  & 1)*15) >=45
 
}