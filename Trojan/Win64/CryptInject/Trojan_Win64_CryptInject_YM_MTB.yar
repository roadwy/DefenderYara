
rule Trojan_Win64_CryptInject_YM_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 01 84 c0 74 90 01 01 3c 90 01 01 74 90 01 01 34 90 01 01 88 01 ff c2 48 ff c1 41 3b d0 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}