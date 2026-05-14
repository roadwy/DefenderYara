
rule Trojan_BAT_DCRat_BAR_MTB{
	meta:
		description = "Trojan:BAT/DCRat.BAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 14 00 00 0a 0c 07 08 ?? ?? 00 00 0a 08 ?? ?? 00 00 0a 0d de 1e 08 2c 06 08 ?? ?? 00 00 0a dc 07 2c 06 07 ?? ?? 00 00 0a dc } //2
		$a_81_1 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}