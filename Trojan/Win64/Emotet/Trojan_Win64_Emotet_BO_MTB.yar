
rule Trojan_Win64_Emotet_BO_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b c3 ff c3 8d 14 52 c1 e2 90 01 01 2b c2 48 63 d0 48 8b 05 90 01 04 8a 14 02 41 32 14 3f 88 17 48 ff c7 49 ff ce 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}