
rule Trojan_Win64_CryptInject_KPM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.KPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 f7 e8 c1 fa 90 01 01 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 35 41 0f b6 c0 2a c1 04 34 41 30 01 41 ff c0 4d 8d 49 01 41 83 f8 15 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}