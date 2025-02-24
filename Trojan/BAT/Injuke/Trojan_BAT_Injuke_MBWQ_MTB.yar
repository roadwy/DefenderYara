
rule Trojan_BAT_Injuke_MBWQ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 44 00 69 00 61 00 67 00 6e 00 6f 00 73 00 74 00 69 00 63 00 73 00 2e 00 53 00 74 00 61 00 63 00 6b 00 54 00 72 00 61 00 63 00 65 00 } //2 System.Diagnostics.StackTrace
		$a_01_1 = {61 00 4f 00 79 00 48 00 4e 00 00 47 62 00 61 } //1
		$a_01_2 = {6c 00 64 00 72 00 2e 00 65 00 78 00 65 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}