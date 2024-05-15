
rule Trojan_Win32_Glupteba_CCHZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d0 8b 45 90 01 01 33 c2 8b 55 90 01 01 2b f8 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}