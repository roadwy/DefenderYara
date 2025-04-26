
rule Trojan_Win32_Small_DL{
	meta:
		description = "Trojan:Win32/Small.DL,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b9 1a 00 00 00 f7 f1 0f b7 d2 83 c2 61 8b 85 fc f7 ff ff 66 89 94 45 04 f8 ff ff eb b1 } //1
		$a_01_1 = {68 49 66 73 20 8b 85 00 f8 ff ff 50 6a 00 e8 } //1
		$a_01_2 = {66 c7 85 8e fb ff ff 6d 00 66 c7 85 90 fb ff ff 73 00 66 c7 85 92 fb ff ff 76 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}