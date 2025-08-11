
rule Trojan_BAT_Filecoder_EBIO_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.EBIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 0b 03 1b 5a 03 1d 63 5f 03 1f 0c 63 60 1f 7f 5f 0c 03 1f 2a 03 1f 0a 63 5f 5a 03 1e 63 61 1f 3f 5f 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}