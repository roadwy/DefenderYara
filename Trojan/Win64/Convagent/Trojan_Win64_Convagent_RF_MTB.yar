
rule Trojan_Win64_Convagent_RF_MTB{
	meta:
		description = "Trojan:Win64/Convagent.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 76 31 6b 67 61 31 4c 55 63 67 52 79 4f 30 5a 76 76 7a 6e 30 2f 39 69 4b 4b 41 66 79 48 42 79 4f 4b 54 57 47 67 64 51 49 4c 2f 51 4b 68 6e 58 63 43 68 74 43 65 43 30 50 6e 33 6d 35 73 30 2f 56 4f 62 50 4c 31 68 6b 75 49 63 6a 49 63 53 7a 55 62 64 53 } //1 Go build ID: "v1kga1LUcgRyO0Zvvzn0/9iKKAfyHByOKTWGgdQIL/QKhnXcChtCeC0Pn3m5s0/VObPL1hkuIcjIcSzUbdS
	condition:
		((#a_01_0  & 1)*1) >=1
 
}