
rule Trojan_Win32_Glupteba_NP_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 31 81 ff 90 02 04 90 18 46 3b f7 90 18 81 ff 90 02 04 90 18 e8 90 02 04 8b 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}