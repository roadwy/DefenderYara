
rule Trojan_BAT_NjRat_MBJX_MTB{
	meta:
		description = "Trojan:BAT/NjRat.MBJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 04 00 fe 0c 03 00 6f ?? 00 00 0a 5a 58 fe 0e 05 00 20 00 00 00 00 fe 0e 06 00 38 98 00 00 00 fe 09 00 00 fe 0c 06 00 fe 0c 04 00 28 ?? 00 00 0a fe 0e 07 00 fe 0c 05 00 fe 0c 06 00 } //1
		$a_01_1 = {34 35 39 33 2d 42 34 35 38 2d 32 45 44 37 31 33 44 45 41 37 45 31 } //1 4593-B458-2ED713DEA7E1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}