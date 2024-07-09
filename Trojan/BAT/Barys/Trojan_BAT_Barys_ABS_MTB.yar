
rule Trojan_BAT_Barys_ABS_MTB{
	meta:
		description = "Trojan:BAT/Barys.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 0f 2b 38 11 0e 11 0f 9a 13 10 00 11 10 6f ?? ?? ?? 0a 7e 0f 00 00 04 16 28 ?? ?? ?? 0a 16 fe 01 13 11 11 11 13 12 11 12 2c 0a 00 11 10 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}