
rule Trojan_BAT_Filecoder_PSSE_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.PSSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {26 07 06 6f 30 00 00 0a 16 73 2c 00 00 0a 0c 00 04 18 73 29 00 00 0a 0d 00 20 00 00 10 00 8d 2a 00 00 01 13 04 2b 0e } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}