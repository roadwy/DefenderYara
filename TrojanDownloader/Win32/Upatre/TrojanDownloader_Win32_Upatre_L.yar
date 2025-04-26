
rule TrojanDownloader_Win32_Upatre_L{
	meta:
		description = "TrojanDownloader:Win32/Upatre.L,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {00 55 70 64 61 74 65 73 20 64 6f 77 6e 6c 6f 61 64 65 72 00 } //  1
		$a_03_1 = {8b 48 3c 89 45 ?? 81 e1 ff ff 00 00 03 c1 b9 18 00 00 00 03 c1 } //1
		$a_03_2 = {3d 5a 5a 50 00 0f ?? ?? 00 00 00 8b 45 ?? c1 e0 02 89 45 ?? 50 6a 08 ff 75 ?? ff 55 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}