
rule Trojan_Win32_Ponystealer_SOB_MTB{
	meta:
		description = "Trojan:Win32/Ponystealer.SOB!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 75 6d 69 6c 69 61 74 6f 72 35 } //2 Humiliator5
		$a_01_1 = {46 72 6f 6e 74 61 6c 73 61 6d 6d 65 6e 73 74 64 36 } //2 Frontalsammenstd6
		$a_01_2 = {53 6b 65 6c 65 74 74 65 72 69 6e 67 73 } //2 Skeletterings
		$a_01_3 = {54 61 70 73 61 6d 6c 69 6e 67 65 72 31 } //2 Tapsamlinger1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}