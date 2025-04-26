
rule Trojan_BAT_Bladabindi_NEI_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 06 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 06 28 ?? 00 00 0a 20 ?? 04 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 7e ?? 00 00 0a 26 de 03 } //1
		$a_01_1 = {52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //1 RegAsm.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}