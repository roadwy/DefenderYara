
rule Trojan_Win32_ModiLoader_AMR_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d6 8b c3 ff 15 90 01 04 84 db 75 0d e8 90 01 04 8b 98 00 00 00 00 eb 0f 80 fb 18 77 0a 33 c0 8a c3 8a 98 38 30 00 10 33 c0 8a c3 8b d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}