
rule Trojan_Win64_IcedID_MAL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 35 34 49 70 77 50 45 } //1 A54IpwPE
		$a_01_1 = {41 48 34 6a 61 50 51 4c 32 43 7a } //1 AH4jaPQL2Cz
		$a_01_2 = {42 74 4b 47 59 6b 6f 59 78 } //1 BtKGYkoYx
		$a_01_3 = {43 75 78 6f 46 4c 79 50 39 } //1 CuxoFLyP9
		$a_01_4 = {44 35 5a 63 4d 50 42 34 6d } //1 D5ZcMPB4m
		$a_01_5 = {46 67 48 4d 4f 74 43 72 5a 49 } //1 FgHMOtCrZI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}