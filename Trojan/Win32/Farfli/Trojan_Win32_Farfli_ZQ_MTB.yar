
rule Trojan_Win32_Farfli_ZQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 55 ec 8a 1c 11 80 c3 7a 88 1c 11 8b 55 ec 8a 1c 11 80 f3 59 88 1c 11 41 3b c8 7c e3 } //1
		$a_00_1 = {8b 55 0c 40 8a 0a 42 88 48 ff 84 c9 74 0a } //1
		$a_80_2 = {73 6b 79 62 6c 75 65 68 61 63 6b 65 72 40 79 61 68 6f 6f 2e 63 6f 6d 2e 63 6e } //skybluehacker@yahoo.com.cn  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}