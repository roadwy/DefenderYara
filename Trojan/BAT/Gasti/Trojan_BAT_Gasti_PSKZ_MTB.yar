
rule Trojan_BAT_Gasti_PSKZ_MTB{
	meta:
		description = "Trojan:BAT/Gasti.PSKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 25 00 00 0a 1f 0a 1f 14 6f ?? ?? ?? 0a 0a 06 28 17 00 00 06 72 5f 00 00 70 28 ?? ?? ?? 0a 0b 07 72 5f 00 00 70 72 69 00 00 70 6f ?? ?? ?? 0a 0c 06 28 17 00 00 06 0d 28 0b 00 00 06 72 73 00 00 70 09 72 73 00 00 70 28 ?? ?? ?? 0a 13 04 72 77 00 00 70 72 77 00 00 70 72 83 00 00 70 28 ?? ?? ?? 0a 26 28 11 00 00 06 28 1c 00 00 06 13 05 11 05 17 8d 2c 00 00 01 25 16 1f 0a 9d 6f 2a 00 00 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}