
rule Trojan_Win32_Conti_GA_MTB{
	meta:
		description = "Trojan:Win32/Conti.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {48 0d 00 ff ff ff 40 0f b6 80 90 01 04 33 90 01 01 8b 15 90 01 04 03 55 90 01 01 88 0a 90 0a 28 00 03 c2 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Conti_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Conti.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {03 45 d4 0f be 08 8b 15 90 01 04 0f b6 82 90 01 04 8b 15 90 01 04 0f b6 92 90 01 04 03 c2 25 90 01 04 90 18 0f b6 80 90 01 04 33 c8 8b 15 90 01 04 03 55 d4 88 0a e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}