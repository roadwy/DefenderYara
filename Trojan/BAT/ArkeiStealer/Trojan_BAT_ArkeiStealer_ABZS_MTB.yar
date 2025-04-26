
rule Trojan_BAT_ArkeiStealer_ABZS_MTB{
	meta:
		description = "Trojan:BAT/ArkeiStealer.ABZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 02 16 03 8e 69 28 ?? 00 00 06 13 90 0a 15 00 7e ?? 00 00 04 28 } //2
		$a_01_1 = {44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 6c 00 4a 00 6f 00 62 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}