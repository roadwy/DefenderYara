
rule Trojan_Win32_Zusy_GMH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c2 83 e0 07 b9 90 01 04 2b c8 b0 01 d2 e0 8a 0e 0a c8 88 0e 8b 74 24 20 8b 44 24 10 42 3b d0 0f 82 90 01 04 8b 44 24 14 47 3b f8 0f 82 90 00 } //01 00 
		$a_01_1 = {5f 66 6e 50 44 46 54 6f 54 65 78 74 40 38 } //01 00  _fnPDFToText@8
		$a_01_2 = {44 75 6c 64 74 6c 20 45 75 6d 64 75 } //00 00  Duldtl Eumdu
	condition:
		any of ($a_*)
 
}