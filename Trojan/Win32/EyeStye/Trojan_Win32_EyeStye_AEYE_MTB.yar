
rule Trojan_Win32_EyeStye_AEYE_MTB{
	meta:
		description = "Trojan:Win32/EyeStye.AEYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 00 a4 00 a2 ?? ?? ?? ?? e0 cb 00 00 94 08 00 a4 00 a2 ?? ?? ?? ?? e1 cb 00 00 94 08 00 a4 00 a2 ?? ?? ?? ?? e2 cb 00 00 94 08 00 a4 } //3
		$a_01_1 = {54 46 4f 4e 49 4c 41 4b 6c 51 45 59 65 74 4c 66 5a 59 6f 45 } //2 TFONILAKlQEYetLfZYoE
		$a_01_2 = {6b 45 59 65 64 53 4d 75 5a 70 44 77 56 4b 55 57 50 4f 49 52 } //1 kEYedSMuZpDwVKUWPOIR
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}