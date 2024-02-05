
rule Trojan_Win32_Redcape_RPR_MTB{
	meta:
		description = "Trojan:Win32/Redcape.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d ec 8b 75 cc 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d c8 89 75 dc 89 4d d8 89 55 d4 } //00 00 
	condition:
		any of ($a_*)
 
}