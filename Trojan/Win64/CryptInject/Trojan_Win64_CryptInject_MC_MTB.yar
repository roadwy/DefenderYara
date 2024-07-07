
rule Trojan_Win64_CryptInject_MC_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 63 00 6f 00 6d 00 3a 00 38 00 30 00 2f 00 61 00 70 00 69 00 2f 00 76 00 31 00 2e 00 35 00 2f 00 73 00 75 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 3f 00 74 00 6f 00 6b 00 65 00 6e 00 3d 00 } //1 http://finformservice.com:80/api/v1.5/subscription?token=
		$a_03_1 = {48 63 44 24 90 01 01 48 8b 4c 24 90 01 01 0f b6 04 01 8b 4c 24 90 01 01 c1 e1 03 48 8b 54 24 90 01 01 48 8b 52 90 01 01 48 d3 ea 48 8b ca 0f b6 c9 33 c1 48 63 4c 24 90 01 01 88 44 0c 28 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}