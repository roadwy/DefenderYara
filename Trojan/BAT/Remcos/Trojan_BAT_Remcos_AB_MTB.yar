
rule Trojan_BAT_Remcos_AB_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {3a 5a 01 00 00 11 07 02 6f ?? 00 00 0a 3c 4d 01 00 00 11 08 02 6f ?? 00 00 0a 3c 11 01 00 00 06 6f ?? 00 00 0a 03 3c 34 01 00 00 02 11 07 11 08 6f ?? 00 00 0a 13 09 03 06 6f ?? 00 00 0a 59 13 0a 11 0a 11 04 61 16 2f 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Remcos_AB_MTB_2{
	meta:
		description = "Trojan:BAT/Remcos.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {1d 00 00 8d 13 00 00 01 25 d0 02 00 00 04 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 12 02 fe 16 0a 00 00 01 6f ?? 00 00 0a 72 01 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 07 06 28 ?? 00 00 0a 00 73 0e 00 00 0a 13 06 11 06 72 0b 00 00 70 6f ?? 00 00 0a 00 11 06 72 1b 00 00 70 07 72 25 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 06 17 6f ?? 00 00 0a 00 11 06 17 } //6
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //2 set_UseShellExecute
		$a_03_2 = {72 6f 67 72 61 6d 44 61 74 61 5c [0-0a] 2e 62 61 74 27 20 2d 46 6f 72 63 65 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 22 } //2
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*2+(#a_03_2  & 1)*2) >=10
 
}