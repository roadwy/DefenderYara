
rule Trojan_Win32_Glupteba_ICAA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ICAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 30 04 0e 83 ff 0f 75 24 6a 00 6a 00 6a 00 ff d3 68 } //00 00 
	condition:
		any of ($a_*)
 
}