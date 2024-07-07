
rule Trojan_BAT_Taskun_FAT_MTB{
	meta:
		description = "Trojan:BAT/Taskun.FAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 2b 20 00 07 09 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 13 05 08 11 05 6f 90 01 01 00 00 0a 00 09 18 58 0d 00 09 07 6f 90 01 01 00 00 0a fe 04 13 06 11 06 2d d1 90 00 } //3
		$a_01_1 = {56 00 65 00 6e 00 64 00 65 00 42 00 65 00 6d 00 56 00 65 00 69 00 63 00 75 00 6c 00 6f 00 73 00 5f 00 50 00 61 00 74 00 74 00 65 00 72 00 6e 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 VendeBemVeiculos_Patterns.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}