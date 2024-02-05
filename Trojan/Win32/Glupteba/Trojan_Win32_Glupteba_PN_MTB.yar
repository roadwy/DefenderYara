
rule Trojan_Win32_Glupteba_PN_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 33 45 f0 89 45 e4 8b 45 e4 33 45 ec 89 45 e4 8b 45 d0 2b 45 e4 89 45 d0 8b 45 e8 2b 45 d8 89 45 e8 e9 90 02 04 8b 45 08 8b 4d d0 89 08 8b 45 08 8b 4d f4 89 48 04 c9 c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}