
rule Trojan_BAT_AsyncRAT_BGD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 0c 11 0d 11 04 11 05 ?? ?? 00 00 0a 16 ?? ?? 00 00 0a 13 0e 11 0e 11 0b ?? ?? 00 00 0a 00 de 0e 00 11 0e 2c 08 11 0e ?? ?? 00 00 0a 00 dc de 0e 00 11 0d 2c 08 11 0d ?? ?? 00 00 0a 00 dc de 0e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}