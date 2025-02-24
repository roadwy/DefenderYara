
rule Trojan_Win32_FileCoder_ARAC_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 75 18 8a 8c 95 fc fb ff ff 8a 14 30 32 d1 88 14 30 40 3b c7 0f 82 70 ff ff ff } //2
		$a_01_1 = {8b 55 18 03 95 f4 fb ff ff 8a 0a 32 8c 85 f8 fb ff ff 8b 55 18 03 95 f4 fb ff ff 88 0a e9 2e ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}