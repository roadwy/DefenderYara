
rule Trojan_BAT_Stealer_MZ_MTB{
	meta:
		description = "Trojan:BAT/Stealer.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {16 17 9c 25 0c 28 90 01 02 00 0a 0d 08 16 91 2d 02 2b 1e 07 16 9a 28 90 01 02 00 0a d0 01 00 00 1b 28 90 01 02 00 0a 28 90 01 02 00 0a 74 01 00 00 1b 10 00 09 74 90 01 02 00 01 0a 2b 00 06 2a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}