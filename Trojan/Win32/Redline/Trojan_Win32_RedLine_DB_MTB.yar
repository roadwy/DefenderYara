
rule Trojan_Win32_RedLine_DB_MTB{
	meta:
		description = "Trojan:Win32/RedLine.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be 06 33 c1 69 c0 91 e9 d1 5b 33 f8 8b c7 c1 e8 0d 33 c7 69 c0 91 e9 d1 5b 8b c8 c1 e9 0f 33 c8 74 06 3b 4c 24 54 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}