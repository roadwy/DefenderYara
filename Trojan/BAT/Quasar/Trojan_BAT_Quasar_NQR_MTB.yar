
rule Trojan_BAT_Quasar_NQR_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 13 00 00 0a 0b 07 07 8e 69 18 59 28 ?? ?? 00 0a 0c 08 20 ?? ?? 00 00 fe 01 13 05 11 05 39 ?? ?? 00 00 } //5
		$a_01_1 = {53 69 4d 61 79 53 65 72 76 69 63 65 2e 4c 6f 61 64 65 72 } //1 SiMayService.Loader
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}