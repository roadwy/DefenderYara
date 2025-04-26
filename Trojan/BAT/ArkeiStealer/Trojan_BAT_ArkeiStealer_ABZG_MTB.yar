
rule Trojan_BAT_ArkeiStealer_ABZG_MTB{
	meta:
		description = "Trojan:BAT/ArkeiStealer.ABZG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 8e 69 28 ?? 00 00 06 13 03 90 0a 1b 00 11 04 6f ?? 00 00 0a 7e ?? 00 00 04 16 7e } //2
		$a_01_1 = {44 61 74 61 42 61 73 65 50 72 61 63 74 69 63 61 6c 4a 6f 62 } //1 DataBasePracticalJob
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}