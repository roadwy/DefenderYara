
rule Trojan_BAT_Vidar_MBBI_MTB{
	meta:
		description = "Trojan:BAT/Vidar.MBBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 11 0d 16 11 0b 6f ?? 00 00 0a 25 26 26 11 0a 11 0d 16 11 0b 11 0c 16 6f 8e 00 00 0a 25 26 13 0f 7e 35 00 00 04 11 0c 16 11 0f 6f 8f 00 00 0a 11 0e 11 0b 58 13 0e 11 0e 11 0b 58 6a 06 6f 87 00 00 0a 25 26 32 b9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}