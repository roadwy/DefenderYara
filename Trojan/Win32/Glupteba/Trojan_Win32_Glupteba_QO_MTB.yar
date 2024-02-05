
rule Trojan_Win32_Glupteba_QO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 90 02 02 8b 90 02 02 03 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 29 90 02 02 8b 90 02 02 51 8d 90 02 02 52 e8 90 02 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}