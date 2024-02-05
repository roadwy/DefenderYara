
rule Trojan_Win64_CryptInject_PA_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {45 84 c0 75 90 01 01 49 3b ca 73 90 01 01 49 8b c1 83 e0 7f 42 0f b6 04 18 30 01 48 ff c1 49 ff c1 48 83 ea 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}