
rule Trojan_BAT_Dcstl_NDT_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 1f 00 00 06 0d 09 17 6f ?? 00 00 0a 09 04 07 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 03 6f ?? 00 00 0a 13 07 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 08 11 05 } //5
		$a_01_1 = {4c 61 73 65 72 50 72 69 6e 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 LaserPrinter.Properties.Resources
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}