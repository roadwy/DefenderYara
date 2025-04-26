
rule Trojan_BAT_Remcos_NEF_MTB{
	meta:
		description = "Trojan:BAT/Remcos.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 06 00 00 06 25 6f 07 00 00 06 25 6f 08 00 00 06 25 6f 09 00 00 06 2b 01 2a 6f 0a 00 00 06 2b f8 } //5
		$a_01_1 = {2b c9 02 2b cd 28 01 00 00 06 2b cd 28 1b 00 00 0a 2b c8 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4) >=9
 
}
rule Trojan_BAT_Remcos_NEF_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {09 04 03 8e 69 28 ?? 00 00 06 d6 13 04 11 04 04 5f 13 05 09 03 8e 69 28 ?? 00 00 06 13 06 03 11 06 91 13 07 11 07 11 05 } //1
		$a_01_1 = {41 00 73 00 53 00 73 00 4d 00 6d 00 42 00 } //1 AsSsMmB
		$a_01_2 = {40 00 53 00 79 00 73 00 74 00 65 00 6d 00 40 00 2e 00 40 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 40 00 2e 00 40 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 40 00 } //1 @System@.@Reflection@.@Assembly@
		$a_01_3 = {40 00 40 00 40 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 40 00 40 00 40 00 } //1 @@@Method0@@@
		$a_01_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
		$a_01_5 = {25 00 63 00 30 00 6a 00 6d 00 30 00 64 00 73 00 } //1 %c0jm0ds
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}