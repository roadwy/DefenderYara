
rule TrojanDownloader_Win32_Vundo_HIY{
	meta:
		description = "TrojanDownloader:Win32/Vundo.HIY,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {47 45 54 20 75 04 33 ?? eb 0b 81 ?? 50 4f 53 54 75 ?? 6a 04 } //3
		$a_00_1 = {c7 07 68 74 74 70 c7 47 04 3a 2f 2f 00 83 c7 07 } //3
		$a_00_2 = {81 3e 77 77 77 2e 75 03 83 c6 04 } //3
		$a_00_3 = {81 7c 11 fd 0d 0a 0d 0a } //1
		$a_00_4 = {81 7c 0a fd 0d 0a 0d 0a } //1
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=10
 
}