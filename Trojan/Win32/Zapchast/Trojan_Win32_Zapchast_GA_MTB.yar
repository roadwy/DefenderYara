
rule Trojan_Win32_Zapchast_GA_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {89 86 d0 00 00 00 89 7c 24 10 e8 7f 11 00 00 89 44 24 14 8b 44 24 20 2b c3 99 33 c2 2b c2 89 44 24 0c db 44 24 0c dc 0d 90 01 04 e8 5d 11 00 00 db 44 24 2c db 44 24 10 89 44 24 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}