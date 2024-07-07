
rule TrojanDownloader_Win32_Tofsee_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Tofsee.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 c7 40 01 6a 70 c6 40 03 67 eb } //1
		$a_01_1 = {8a 14 06 32 55 14 88 10 8a d1 02 55 18 f6 d9 00 55 14 40 4f 75 ea } //1
		$a_03_2 = {57 83 c3 03 6a 3a 53 e8 90 01 04 8b f8 59 59 85 ff 74 10 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}