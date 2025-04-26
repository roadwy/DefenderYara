
rule Trojan_BAT_Remcos_RPX_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 1a 58 19 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 b2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_RPX_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 17 13 04 16 13 05 2b 23 00 06 09 11 05 58 91 07 11 05 91 fe 01 16 fe 01 13 06 11 06 2c 06 00 16 13 04 2b 14 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 07 11 07 2d d0 } //1
		$a_01_1 = {40 00 72 00 68 00 4d 00 2a 00 41 00 7a 00 41 00 21 00 37 00 25 00 63 00 40 00 50 00 34 00 6f 00 62 00 7a 00 44 00 38 00 73 00 } //1 @rhM*AzA!7%c@P4obzD8s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_Remcos_RPX_MTB_3{
	meta:
		description = "Trojan:BAT/Remcos.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {31 00 34 00 31 00 2e 00 39 00 38 00 2e 00 36 00 2e 00 32 00 30 00 32 00 } //1 141.98.6.202
		$a_01_1 = {49 00 6e 00 61 00 6a 00 6d 00 6c 00 6c 00 62 00 77 00 2e 00 64 00 61 00 74 00 } //1 Inajmllbw.dat
		$a_01_2 = {39 00 73 00 79 00 51 00 57 00 49 00 54 00 2b 00 43 00 5a 00 53 00 45 00 62 00 36 00 68 00 54 00 4d 00 50 00 4e 00 51 00 47 00 41 00 3d 00 3d 00 } //1 9syQWIT+CZSEb6hTMPNQGA==
		$a_01_3 = {39 00 39 00 51 00 56 00 71 00 70 00 6b 00 79 00 73 00 4d 00 51 00 3d 00 } //1 99QVqpkysMQ=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}