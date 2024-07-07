
rule Trojan_BAT_Vidar_NR_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 2d 06 d0 5d 90 01 02 06 26 06 07 6f 90 01 03 0a 25 26 0c 1f 61 6a 08 28 90 01 03 06 25 26 0d 09 28 90 01 03 0a 90 00 } //5
		$a_01_1 = {61 6e 6e 6f 74 61 74 69 6f 6e 2e 6f 70 74 69 6d 69 7a 61 74 69 6f 6e 2e 43 72 69 74 69 63 61 6c 4e 61 74 69 76 65 2e 6d 6f 64 75 6c 65 36 } //1 annotation.optimization.CriticalNative.module6
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}