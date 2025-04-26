
rule Trojan_BAT_FileCoder_RP_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 02 00 00 06 06 20 c3 01 00 00 58 0a 2a } //1
		$a_03_1 = {06 1f 42 58 0a 7e ?? ?? ?? ?? 06 1f 35 59 97 29 ?? ?? ?? ?? 7e ?? ?? ?? ?? 06 1f 34 59 97 29 ?? ?? ?? ?? 2c 02 17 2a 16 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}