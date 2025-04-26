
rule Trojan_BAT_Stealer_SX_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 2d 00 00 0a 06 28 ?? ?? ?? 0a 0c 08 73 2e 00 00 0a 02 28 2f 00 00 0a 28 ?? ?? ?? 0a 73 1b 00 00 0a 25 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}