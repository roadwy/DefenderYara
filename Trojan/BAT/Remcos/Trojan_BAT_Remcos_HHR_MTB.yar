
rule Trojan_BAT_Remcos_HHR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c } //6
		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0a 06 05 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}