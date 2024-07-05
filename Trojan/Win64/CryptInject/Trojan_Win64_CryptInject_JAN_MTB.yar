
rule Trojan_Win64_CryptInject_JAN_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.JAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 63 ca 8d 42 d2 ff c2 30 44 0c 90 01 01 83 fa 0c 72 90 00 } //01 00 
		$a_03_1 = {48 8b c2 48 8d 49 01 83 e0 07 48 ff c2 0f b6 44 04 90 01 01 30 41 ff 49 83 e8 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}