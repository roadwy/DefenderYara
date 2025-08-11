
rule Trojan_BAT_Filecoder_SWA_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 16 07 8e 69 6f ?? 00 00 0a 13 04 08 09 07 11 04 93 9d 09 17 58 0d 09 1f 1b 32 e4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}