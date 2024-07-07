
rule Trojan_BAT_RedLine_SPRT_MTB{
	meta:
		description = "Trojan:BAT/RedLine.SPRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 fe 09 00 00 fe 0c 03 00 6f 90 01 03 0a fe 0c 00 00 fe 0c 03 00 fe 0c 00 00 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 fe 0e 05 00 fe 0d 05 00 28 90 01 03 0a 28 90 01 03 0a fe 0e 01 00 20 00 00 00 00 fe 0e 06 00 38 18 00 00 00 90 00 } //3
		$a_01_1 = {67 65 74 5f 5f 76 6f 74 44 67 79 30 51 65 59 6b 54 72 } //1 get__votDgy0QeYkTr
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}