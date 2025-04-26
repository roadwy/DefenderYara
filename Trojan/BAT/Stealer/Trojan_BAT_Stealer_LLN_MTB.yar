
rule Trojan_BAT_Stealer_LLN_MTB{
	meta:
		description = "Trojan:BAT/Stealer.LLN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {17 13 1f 16 13 20 2b 43 00 02 11 20 02 11 20 91 66 d2 9c 02 11 20 8f 21 00 00 01 25 71 21 00 00 01 1f 64 58 d2 81 21 00 00 01 02 11 20 8f 21 00 00 01 25 71 21 00 00 01 20 92 00 00 00 59 d2 81 21 00 00 01 00 11 20 17 58 13 20 11 20 02 8e 69 fe 04 13 21 11 21 2d b0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}