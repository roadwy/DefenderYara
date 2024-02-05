
rule Trojan_Win32_Staser_AS_MTB{
	meta:
		description = "Trojan:Win32/Staser.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c5 0f b7 db 83 c4 10 66 f7 d6 5b e9 90 01 04 33 c2 1b d6 d2 f6 0f ac fa 57 8b 54 24 18 88 04 2a 80 c4 5b 3a cd d2 ec 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}