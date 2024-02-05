
rule Trojan_Win32_Glupteba_PQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b e5 5d c2 90 09 3e 00 8b 90 01 02 33 90 01 02 89 90 01 02 8b 90 01 02 33 90 01 02 89 90 01 02 8b 90 01 02 2b 90 01 02 89 90 01 02 8b 90 01 02 52 8d 90 01 02 50 e8 90 01 04 e9 90 01 04 8b 90 01 02 8b 90 01 02 89 90 01 01 8b 90 01 02 8b 90 01 02 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}