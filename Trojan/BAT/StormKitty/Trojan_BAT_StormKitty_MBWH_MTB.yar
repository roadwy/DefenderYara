
rule Trojan_BAT_StormKitty_MBWH_MTB{
	meta:
		description = "Trojan:BAT/StormKitty.MBWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 60 0c 03 19 8d ?? 00 00 01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 ?? 28 ?? 00 00 0a 9c 25 18 } //2
		$a_01_1 = {4c 00 6f 00 61 00 64 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}