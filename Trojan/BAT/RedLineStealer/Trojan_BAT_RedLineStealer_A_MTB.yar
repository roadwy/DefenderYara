
rule Trojan_BAT_RedLineStealer_A_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 20 00 00 00 00 6f ?? 00 00 0a fe 0c 03 00 fe 0c 02 00 5d 6f ?? 00 00 0a 6f ?? 00 00 0a 61 d2 9c } //2
		$a_01_1 = {20 15 00 00 00 58 d2 6f } //2
		$a_01_2 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}