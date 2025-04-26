
rule TrojanDownloader_Win32_Carberp_BT{
	meta:
		description = "TrojanDownloader:Win32/Carberp.BT,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e2 04 8d 54 0a d0 89 c1 83 e1 01 40 85 c9 74 08 89 c1 d1 f9 88 54 0c 3b 83 f8 20 } //10
		$a_01_1 = {8a 04 2a 32 06 88 07 47 43 46 45 39 6c 24 24 0f 9f c1 83 fb 0f 0f 9e c0 84 c1 75 } //5
		$a_01_2 = {8a 04 29 32 06 88 04 29 88 07 47 46 45 eb 0a 31 ed 89 d0 29 f0 89 44 24 24 8b 4c 24 24 01 f1 89 4c 24 10 83 f9 0f 7f } //5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}