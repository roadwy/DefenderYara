
rule Trojan_BAT_NanoCore_PLAH_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.PLAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 05 03 11 05 91 11 04 61 06 08 91 61 b4 9c 08 02 6f ?? 00 00 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 06 31 d1 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}