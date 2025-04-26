
rule Trojan_BAT_LummaStealer_K_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 } //4
		$a_01_1 = {06 17 58 0a 06 02 8e 69 fe 04 0b 07 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}