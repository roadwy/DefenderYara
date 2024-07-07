
rule Trojan_BAT_Dcstl_NST_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.NST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {7b d4 01 00 04 72 90 01 03 70 6f 90 01 03 0a 28 90 01 03 0a 25 72 90 01 03 70 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 28 90 01 03 0a 90 00 } //5
		$a_01_1 = {41 49 4f 5f 54 6f 6f 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 AIO_Tool.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}