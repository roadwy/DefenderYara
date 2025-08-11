
rule Trojan_BAT_AsyncRAT_JKI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.JKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 6f 85 00 00 0a 28 50 00 00 06 0c 73 5c 00 00 0a 28 4f 00 00 06 0d 09 07 6f 81 00 00 0a 09 08 6f 82 00 00 0a 25 09 6f 86 00 00 0a 17 73 5d 00 00 0a 25 06 16 06 8e 69 6f 5e 00 00 0a 6f 61 00 00 0a 6f 60 00 00 0a 28 87 00 00 0a 2a } //2
		$a_00_1 = {43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 CCCCCCCCCCCCCCCCCCCCCCCCCCCC.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}