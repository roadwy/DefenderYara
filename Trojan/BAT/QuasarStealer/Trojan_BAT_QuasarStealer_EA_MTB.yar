
rule Trojan_BAT_QuasarStealer_EA_MTB{
	meta:
		description = "Trojan:BAT/QuasarStealer.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 6f 20 00 00 0a 5d 6f 21 00 00 0a 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}