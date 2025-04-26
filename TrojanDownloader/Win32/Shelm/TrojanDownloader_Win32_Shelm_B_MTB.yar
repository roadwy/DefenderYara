
rule TrojanDownloader_Win32_Shelm_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/Shelm.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c2 89 c1 83 c5 ?? d1 ea 89 d0 f7 e3 c1 ea ?? 6b d2 ?? 29 d1 0f b6 81 } //2
		$a_01_1 = {4d 6f 7a 69 6c 6c 61 2f 34 } //2 Mozilla/4
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}