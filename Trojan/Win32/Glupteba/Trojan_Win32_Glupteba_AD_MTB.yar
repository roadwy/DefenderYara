
rule Trojan_Win32_Glupteba_AD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {31 3a 42 39 da 75 ec c3 8d 3c 37 8b 3f 40 09 c9 81 e7 90 01 04 29 c0 81 c6 90 01 04 40 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}