
rule Trojan_BAT_Androm_MBCI_MTB{
	meta:
		description = "Trojan:BAT/Androm.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 06 08 8f ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df } //1
		$a_03_1 = {72 11 00 00 70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 a2 } //1
		$a_01_2 = {61 30 61 63 66 64 37 36 37 66 30 36 } //1 a0acfd767f06
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}