
rule Trojan_Win32_Glupteba_QL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.QL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ec 8b 90 02 02 03 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 33 90 02 02 89 90 02 02 8b 90 02 02 29 90 02 02 81 3d 90 02 08 90 18 8b 90 02 02 2b 90 02 02 89 90 02 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}