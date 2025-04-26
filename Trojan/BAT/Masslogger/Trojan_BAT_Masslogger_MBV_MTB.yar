
rule Trojan_BAT_Masslogger_MBV_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.MBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 06 11 04 19 5a 58 1f 18 5d 1f 0c 59 9e 11 04 17 58 13 04 11 04 07 8e 69 fe 04 } //1
		$a_01_1 = {4b 00 49 00 00 09 4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 00 25 4c 00 6f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}