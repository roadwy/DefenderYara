
rule Trojan_Win32_RedLine_DIS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.DIS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 8b fe d3 e7 03 45 d4 89 55 ec 03 7d e0 33 f8 33 fa 89 7d e8 8b 45 e8 29 45 f8 8b 45 d8 29 45 fc ff 4d e4 } //00 00 
	condition:
		any of ($a_*)
 
}