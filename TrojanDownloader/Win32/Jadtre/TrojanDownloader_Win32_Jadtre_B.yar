
rule TrojanDownloader_Win32_Jadtre_B{
	meta:
		description = "TrojanDownloader:Win32/Jadtre.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 44 3d 25 73 26 66 6e 3d 25 73 5f 25 73 26 56 61 72 3d 25 2e 38 58 } //1 ID=%s&fn=%s_%s&Var=%.8X
		$a_00_1 = {25 73 61 75 74 6f 72 75 6e 2e 69 6e 66 } //1 %sautorun.inf
		$a_03_2 = {68 72 72 f2 e1 ff 75 ?? ff 55 ?? 8d 45 ?? 50 ff 75 ?? ff 55 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}