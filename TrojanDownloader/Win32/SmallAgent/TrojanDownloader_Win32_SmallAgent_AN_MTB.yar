
rule TrojanDownloader_Win32_SmallAgent_AN_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 b9 3f 00 00 00 f7 f1 8a 54 15 a0 88 55 ff 8b 45 f4 8a 4d ff 88 08 8b 55 f8 83 ea 01 89 55 f8 8b 45 f4 83 c0 01 89 45 f4 83 7d f8 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}