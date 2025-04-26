
rule Trojan_BAT_Metasploit_AMBF_MTB{
	meta:
		description = "Trojan:BAT/Metasploit.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 49 06 07 06 8e 69 5d 93 61 d1 53 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d dd } //1
		$a_03_1 = {0a 00 0b 07 6f ?? 00 00 0a 0c 08 06 16 06 8e 69 6f ?? 00 00 0a 0d 28 ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 2b 00 11 05 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}