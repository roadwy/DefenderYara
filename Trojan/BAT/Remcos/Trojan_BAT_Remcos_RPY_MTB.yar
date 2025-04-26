
rule Trojan_BAT_Remcos_RPY_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 01 00 6f 67 00 00 0a 20 03 00 00 00 66 20 02 00 00 00 63 65 8d 2e 00 00 01 25 20 40 fc 9e 24 20 bf 03 61 db 58 66 20 b4 be 87 e7 20 01 00 00 00 63 66 20 9e 20 3c 0c 61 9d 6f 68 00 00 0a fe 0e 02 00 20 1c 00 00 00 38 43 e8 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Remcos_RPY_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 18 5a 18 6f 8a 00 00 0a 1f 10 28 8b 00 00 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d dc } //1
		$a_01_1 = {34 00 44 00 35 00 41 00 39 00 7e 00 7e 00 33 00 7e 00 7e 00 7e 00 30 00 34 00 7e 00 7e 00 7e 00 46 00 46 00 46 00 46 00 7e 00 7e 00 42 00 38 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 34 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 7e 00 30 00 38 00 7e 00 7e 00 7e 00 7e 00 } //1 4D5A9~~3~~~04~~~FFFF~~B8~~~~~~~4~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~08~~~~
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}