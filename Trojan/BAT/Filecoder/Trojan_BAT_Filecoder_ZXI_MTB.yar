
rule Trojan_BAT_Filecoder_ZXI_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.ZXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0c 06 08 08 8e 69 12 03 7e ?? 00 00 0a 28 ?? 00 00 06 13 04 11 04 2c 37 00 72 1f 02 00 70 72 39 02 00 70 28 ?? 00 00 0a 26 7e ?? 00 00 0a 72 ?? 02 00 70 6f ?? 00 00 0a 13 05 11 05 72 56 03 00 70 17 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}