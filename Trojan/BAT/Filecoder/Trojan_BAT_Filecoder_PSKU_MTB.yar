
rule Trojan_BAT_Filecoder_PSKU_MTB{
	meta:
		description = "Trojan:BAT/Filecoder.PSKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 65 00 00 70 28 1d 00 00 06 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 72 a5 00 00 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c de 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}