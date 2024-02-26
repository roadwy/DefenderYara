
rule Trojan_Win32_Glupteba_SAP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.SAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 04 33 83 ff 0f 75 0f } //00 00 
	condition:
		any of ($a_*)
 
}