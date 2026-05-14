
rule Trojan_BAT_DarkTortilla_RVC_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 9f a2 2b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 ?? 01 00 00 ?? 00 00 00 2b 03 00 00 ?? 06 00 00 02 00 00 00 01 00 00 00 23 03 00 00 02 00 00 00 4c 00 00 00 08 00 00 00 ?? 00 00 00 04 00 00 00 09 00 00 00 0a 00 00 00 01 00 00 00 6f 00 00 00 09 00 00 00 01 00 00 00 07 00 00 00 04 00 00 00 ?? 00 00 00 21 00 00 00 42 } //2
		$a_81_1 = {6b 65 6c 61 69 6f 78 61 2e 62 61 74 72 65 73 6f 75 72 63 65 73 } //1 kelaioxa.batresources
		$a_81_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}