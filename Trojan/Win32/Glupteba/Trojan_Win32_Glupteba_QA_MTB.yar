
rule Trojan_Win32_Glupteba_QA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 45 d4 01 90 02 02 83 90 02 06 90 18 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 29 90 02 02 8b 90 02 02 29 90 02 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}