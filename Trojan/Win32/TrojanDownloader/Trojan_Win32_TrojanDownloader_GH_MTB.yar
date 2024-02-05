
rule Trojan_Win32_TrojanDownloader_GH_MTB{
	meta:
		description = "Trojan:Win32/TrojanDownloader.GH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {39 d2 74 01 ea 31 0a 47 81 c2 04 00 00 00 4b 39 } //01 00 
		$a_01_1 = {39 ff 74 01 ea 31 1e 81 c6 04 00 00 00 81 e8 d8 bf 14 de 09 c8 39 d6 75 e7 } //00 00 
	condition:
		any of ($a_*)
 
}