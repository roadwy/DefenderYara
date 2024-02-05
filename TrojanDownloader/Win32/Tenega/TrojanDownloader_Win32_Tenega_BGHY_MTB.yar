
rule TrojanDownloader_Win32_Tenega_BGHY_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tenega.BGHY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 89 75 d2 66 89 7d da 66 89 55 84 66 89 4d 8e 66 89 7d 90 66 89 75 ba 66 89 4d bc 66 89 5d c2 66 89 45 c8 } //00 00 
	condition:
		any of ($a_*)
 
}