
rule Trojan_BAT_BluStealer_RDA_MTB{
	meta:
		description = "Trojan:BAT/BluStealer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_03_0 = {00 07 08 09 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 7e ?? ?? ?? ?? 06 28 ?? ?? ?? ?? d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 } //2
		$a_01_1 = {75 00 47 00 2e 00 42 00 31 00 } //1 uG.B1
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_5 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}