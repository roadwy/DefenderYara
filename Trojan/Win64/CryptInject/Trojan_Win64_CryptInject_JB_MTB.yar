
rule Trojan_Win64_CryptInject_JB_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.JB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 2b c8 48 8b 03 42 32 14 21 49 8b c8 48 2b cf 88 14 01 } //00 00 
	condition:
		any of ($a_*)
 
}