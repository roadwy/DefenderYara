
rule Trojan_BAT_LummaStealer_NM_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 10 8d 7e 00 00 01 13 14 11 09 28 ?? 07 00 0a 16 11 14 16 1a 28 ?? 07 00 0a 11 0a 28 ?? 07 00 0a 16 11 14 } //3
		$a_01_1 = {46 65 72 6e 61 6e 64 6f 4b 61 70 5f 64 69 67 69 74 61 6c 45 55 } //1 FernandoKap_digitalEU
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}
rule Trojan_BAT_LummaStealer_NM_MTB_2{
	meta:
		description = "Trojan:BAT/LummaStealer.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0b 00 00 06 73 ?? 00 00 06 7e ?? 00 00 04 7e ?? 00 00 04 6f ?? 00 00 06 15 7e ?? 00 00 04 16 8f ?? 00 00 01 7e ?? 00 00 04 8e 69 1f 40 12 00 28 0a 00 00 06 } //3
		$a_03_1 = {26 16 0b 20 88 01 00 00 0c 16 16 7e ?? 00 00 04 08 8f ?? 00 00 01 7e ?? 00 00 04 16 12 01 28 08 00 00 06 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}