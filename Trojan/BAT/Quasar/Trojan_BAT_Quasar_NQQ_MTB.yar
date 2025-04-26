
rule Trojan_BAT_Quasar_NQQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 03 17 11 04 58 91 11 04 1e 5a 1f 1f 5f 62 58 0d 11 04 17 58 13 04 11 04 1a 3f e1 ff ff ff } //5
		$a_01_1 = {62 79 63 72 70 66 6d 61 6e 68 64 71 75 65 72 70 2e 52 65 73 6f 75 72 63 65 73 } //1 bycrpfmanhdquerp.Resources
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Quasar_NQQ_MTB_2{
	meta:
		description = "Trojan:BAT/Quasar.NQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8c 31 00 00 01 a2 11 07 18 08 28 ?? 00 00 0a a2 11 07 13 06 11 06 14 14 19 8d ?? 00 00 01 13 08 11 08 16 17 9c 11 08 17 16 9c 11 08 18 17 9c 11 08 17 28 ?? 00 00 0a } //5
		$a_01_1 = {4e 61 6e 79 73 65 78 72 66 6d 71 66 75 69 6b 70 64 6b 68 71 62 6e 65 67 73 6b 76 7a } //1 Nanysexrfmqfuikpdkhqbnegskvz
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Quasar_NQQ_MTB_3{
	meta:
		description = "Trojan:BAT/Quasar.NQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 28 19 00 00 0a 28 ?? 00 00 0a 0b 07 07 06 25 13 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a } //5
		$a_01_1 = {43 6c 69 65 6e 74 2d 62 75 69 6c 74 2e 65 78 65 } //1 Client-built.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}