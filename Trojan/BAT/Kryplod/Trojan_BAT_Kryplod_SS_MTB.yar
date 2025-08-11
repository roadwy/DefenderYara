
rule Trojan_BAT_Kryplod_SS_MTB{
	meta:
		description = "Trojan:BAT/Kryplod.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {1d 2c 04 2b 07 2b 0c 1c 2c f6 de 0d 28 10 00 00 06 2b f2 0a 2b f1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}