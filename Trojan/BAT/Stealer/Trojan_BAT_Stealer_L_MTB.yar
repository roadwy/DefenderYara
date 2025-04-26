
rule Trojan_BAT_Stealer_L_MTB{
	meta:
		description = "Trojan:BAT/Stealer.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 03 04 03 8e b7 5d 91 61 02 04 17 58 02 8e b7 5d 91 59 ?? ?? ?? ?? ?? 58 20 00 01 00 00 5d d2 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}