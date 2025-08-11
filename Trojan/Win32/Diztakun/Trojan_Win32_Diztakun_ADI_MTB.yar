
rule Trojan_Win32_Diztakun_ADI_MTB{
	meta:
		description = "Trojan:Win32/Diztakun.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d f8 2b 44 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 f8 2b 44 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01 30 44 11 2d } //2
		$a_03_1 = {b9 18 c3 43 00 e8 ?? ?? ?? ?? b9 24 c3 43 00 e8 ?? ?? ?? ?? b9 34 c3 43 00 e8 ?? ?? ?? ?? b9 48 c3 43 00 e8 ?? ?? ?? ?? b9 48 30 44 00 e8 ?? ?? ?? ?? 6a 06 68 48 30 44 00 ff 15 ?? ?? ?? ?? b9 5c c3 43 00 } //3
		$a_01_2 = {53 68 65 70 61 72 64 2e 52 5f 6d 65 72 67 65 64 5c 52 65 6c 65 61 73 65 5c 53 68 65 70 61 72 64 2e 52 5f 6d 65 72 67 65 64 2e 70 64 62 } //1 Shepard.R_merged\Release\Shepard.R_merged.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=6
 
}