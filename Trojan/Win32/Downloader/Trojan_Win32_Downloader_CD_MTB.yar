
rule Trojan_Win32_Downloader_CD_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 81 b0 00 00 00 0f b7 91 ac 00 00 00 83 f0 fe 66 f7 df c1 e0 0e 66 c1 df 8e 0b c2 0f a3 f7 c1 e0 08 c1 ff d6 66 f7 df 0b 81 a8 00 00 00 c1 e0 08 c1 d7 d1 0b 81 a4 00 00 00 89 04 24 0f b7 7c 24 02 e9 } //01 00 
		$a_01_1 = {f6 da 8b 45 08 8b 10 31 15 80 0f 08 01 c7 45 d8 01 00 00 00 e9 } //00 00 
	condition:
		any of ($a_*)
 
}