
rule TrojanDownloader_Win32_Tedy_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c8 0f b6 81 4d 2d 41 00 30 86 c5 58 41 00 83 c6 06 83 fe 12 0f 82 e9 fe ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}