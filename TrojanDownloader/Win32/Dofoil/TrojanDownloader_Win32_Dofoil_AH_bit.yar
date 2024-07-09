
rule TrojanDownloader_Win32_Dofoil_AH_bit{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 b8 a4 00 00 00 06 [0-30] 89 c6 } //1
		$a_03_1 = {30 d0 aa e2 ?? 75 } //1
		$a_03_2 = {0f b6 46 68 eb [0-20] 40 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}