
rule Trojan_BAT_Stealer_N_MTB{
	meta:
		description = "Trojan:BAT/Stealer.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 1e 11 09 11 24 11 21 61 19 11 18 58 61 11 2f 61 d2 9c 20 1f } //3
		$a_03_1 = {11 08 02 58 20 96 ?? ?? ?? 11 00 58 11 01 61 61 11 0c 20 c5 ?? ?? ?? 11 00 61 11 01 59 5f 61 13 41 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}