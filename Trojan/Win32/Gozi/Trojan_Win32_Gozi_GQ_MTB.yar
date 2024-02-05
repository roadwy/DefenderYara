
rule Trojan_Win32_Gozi_GQ_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {83 ea 05 2b 15 90 01 04 66 89 55 90 01 01 0f b7 45 90 01 01 c1 e0 90 01 01 2b 45 90 01 01 33 c9 a3 90 01 04 89 0d 90 01 04 8b 15 90 01 04 c1 e2 90 01 01 2b 15 90 01 04 88 15 90 01 04 ff 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Gozi_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {f2 0f b6 45 90 01 01 99 03 c1 13 d6 88 45 90 01 01 8b 15 90 02 04 81 c2 90 02 04 89 15 90 02 04 a1 90 02 04 03 45 90 01 01 8b 0d 90 02 04 89 88 90 02 04 0f b7 55 90 01 01 a1 90 02 04 8d 8c 10 90 02 04 0f b6 55 90 01 01 03 ca 0f b6 45 90 01 01 03 c1 88 45 90 01 01 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}