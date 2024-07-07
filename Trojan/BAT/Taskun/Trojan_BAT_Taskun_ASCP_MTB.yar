
rule Trojan_BAT_Taskun_ASCP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ASCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 09 8e 69 5d 09 11 07 09 8e 69 5d 91 11 04 11 07 1f 16 5d 28 90 01 01 00 00 06 61 28 90 01 01 00 00 06 09 11 07 17 58 09 8e 69 5d 91 28 90 01 01 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 01 00 00 06 9c 90 00 } //1
		$a_81_1 = {41 69 72 70 6c 61 6e 65 5f 54 72 61 76 65 6c 6c 69 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Airplane_Travelling.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}