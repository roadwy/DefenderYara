
rule Trojan_Win64_CryptInject_PACO_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.PACO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f3 0f 6f 40 e0 48 8d 40 40 83 c6 40 66 0f 6f ca 66 0f ef c8 f3 0f 7f 48 a0 f3 0f 6f 40 b0 66 0f ef c2 f3 0f 7f 40 b0 f3 0f 6f 48 c0 66 0f ef ca f3 0f 7f 48 c0 66 0f 6f ca f3 0f 6f 40 d0 66 0f ef c8 f3 0f 7f 48 d0 3b f2 72 b5 } //01 00 
		$a_01_1 = {80 31 39 48 8d 49 01 48 83 e8 01 75 f3 } //00 00 
	condition:
		any of ($a_*)
 
}