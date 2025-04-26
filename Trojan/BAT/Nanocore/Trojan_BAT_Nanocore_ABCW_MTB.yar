
rule Trojan_BAT_Nanocore_ABCW_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 07 17 58 0b 07 20 ?? ?? ?? 00 fe 04 0c 08 2d da } //5
		$a_01_1 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 50 00 65 00 72 00 73 00 69 00 61 00 6e 00 44 00 61 00 74 00 65 00 50 00 69 00 63 00 6b 00 65 00 72 00 2e 00 43 00 4f 00 32 00 } //1 WinFormsPersianDatePicker.CO2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}