
rule Trojan_BAT_SystemBC_GKN_MTB{
	meta:
		description = "Trojan:BAT/SystemBC.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 56 bc 11 d2 20 be 6a e4 15 61 20 06 62 4a 18 58 65 20 75 06 9b 05 58 65 20 10 32 a5 da 59 65 66 61 fe 09 00 00 61 d1 9d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}