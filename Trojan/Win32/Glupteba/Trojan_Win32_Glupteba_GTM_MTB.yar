
rule Trojan_Win32_Glupteba_GTM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {be d8 85 40 00 89 ff 81 ef 34 68 a4 a9 e8 90 01 04 29 ff 81 eb 97 48 80 39 31 32 4f 89 ff 42 53 5f 39 c2 75 da 21 ff c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}