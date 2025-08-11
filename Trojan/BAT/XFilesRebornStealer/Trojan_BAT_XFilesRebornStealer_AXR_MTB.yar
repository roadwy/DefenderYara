
rule Trojan_BAT_XFilesRebornStealer_AXR_MTB{
	meta:
		description = "Trojan:BAT/XFilesRebornStealer.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 09 2b 3e 11 08 11 09 9a 13 0a 00 11 0a 6f ?? 00 00 0a 72 ?? 05 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 2d 03 17 2b 01 16 13 0b 11 0a 6f } //2
		$a_01_1 = {78 00 66 00 69 00 6c 00 65 00 73 00 72 00 65 00 62 00 6f 00 72 00 6e 00 2e 00 72 00 75 00 } //3 xfilesreborn.ru
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}