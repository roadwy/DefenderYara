
rule Trojan_BAT_Remcos_ABVC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ABVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 02 6f ?? 00 00 0a 25 26 11 03 1f 18 28 ?? 00 00 06 14 14 11 06 74 ?? 00 00 1b 6f ?? 00 00 0a 25 26 26 38 ?? ff ff ff 28 ?? 00 00 06 25 26 28 ?? 00 00 0a 25 26 13 05 } //3
		$a_01_1 = {32 32 32 30 36 66 62 30 2d 63 39 38 30 2d 34 61 63 38 2d 38 32 39 34 2d 38 36 32 31 35 30 32 63 66 31 38 36 } //1 22206fb0-c980-4ac8-8294-8621502cf186
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}