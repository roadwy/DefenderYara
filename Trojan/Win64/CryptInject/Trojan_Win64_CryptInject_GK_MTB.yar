
rule Trojan_Win64_CryptInject_GK_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.GK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 99 44 8b f4 44 8b d3 4d 63 f7 0f ac c9 b3 41 be bf e5 f1 78 66 45 3b fc 48 8b 50 18 48 83 c2 10 0f 99 c5 } //01 00 
		$a_01_1 = {4c 61 6e 67 44 61 74 61 43 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}