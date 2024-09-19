
rule Trojan_BAT_FileCoder_MA_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 11 00 00 70 28 3a 00 00 06 7e 1e 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}