
rule Trojan_BAT_Noon_HHM_MTB{
	meta:
		description = "Trojan:BAT/Noon.HHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 } //6
		$a_03_1 = {0a 61 d2 0d 90 0a 1a 00 00 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 61 0f 00 28 ?? 00 00 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}