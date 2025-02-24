
rule Trojan_BAT_DarkCloud_AKD_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 06 11 05 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 11 05 17 58 13 05 11 05 06 8e 69 } //2
		$a_01_1 = {6f 00 73 00 68 00 69 00 2e 00 61 00 74 00 2f 00 56 00 56 00 44 00 64 00 } //1 oshi.at/VVDd
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}