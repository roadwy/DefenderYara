
rule Trojan_BAT_DCRat_ADA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {14 fe 03 0b 07 2c 54 00 02 7b 0b 00 00 04 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 02 7b 0c 00 00 04 06 6f ?? ?? ?? 0a 0c 12 02 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 02 7b 0d 00 00 04 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 02 7b 0e 00 00 04 06 6f ?? ?? ?? 0a 17 59 6f } //2
		$a_01_1 = {56 00 65 00 72 00 65 00 73 00 69 00 79 00 65 00 2e 00 55 00 49 00 2e 00 65 00 78 00 65 00 } //1 Veresiye.UI.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}