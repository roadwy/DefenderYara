
rule Trojan_Win32_FileCoder_XZ_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 68 8b 54 24 60 89 50 04 8b 8c 24 90 01 04 5f 5e 89 28 5d 5b 33 cc e8 90 01 02 00 00 81 c4 90 01 02 00 00 c3 90 00 } //1
		$a_03_1 = {8b 44 24 68 8b 54 24 60 89 50 04 eb 90 02 20 8b 8c 24 90 01 04 5f 5e 89 28 5d 5b 33 cc e8 90 01 02 00 00 81 c4 90 01 02 00 00 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}