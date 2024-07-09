
rule Trojan_BAT_DCRat_NTY_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 04 00 00 06 28 ?? ?? ?? 2b 74 ?? ?? ?? 01 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2a } //5
		$a_01_1 = {51 72 6c 79 64 63 73 7a 6f 6f } //1 Qrlydcszoo
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}