
rule Trojan_BAT_Bladabindi_MBFV_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 00 68 00 5a 00 71 00 58 00 51 00 46 00 45 00 45 00 6e 00 6d 00 47 00 74 00 69 00 63 00 4c 00 49 00 62 00 68 00 47 00 4b 00 69 00 4c 00 31 00 6c 00 52 00 38 00 33 00 48 00 4e 00 59 00 39 00 } //1 vhZqXQFEEnmGticLIbhGKiL1lR83HNY9
		$a_01_1 = {52 43 32 4d 44 35 44 65 63 72 79 70 74 } //1 RC2MD5Decrypt
		$a_01_2 = {68 00 62 00 51 00 34 00 6f 00 78 00 36 00 59 00 65 00 5a 00 74 00 35 00 30 00 4b 00 50 00 46 00 30 00 42 00 61 00 4e 00 } //1 hbQ4ox6YeZt50KPF0BaN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}