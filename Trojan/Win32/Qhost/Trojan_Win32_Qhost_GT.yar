
rule Trojan_Win32_Qhost_GT{
	meta:
		description = "Trojan:Win32/Qhost.GT,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {31 32 37 2e 30 2e 30 2e 31 09 77 77 77 2e 73 79 6d 61 6e 74 65 63 2e 63 6f 6d 0a 31 32 37 2e 30 2e 30 2e 31 09 } //1
		$a_03_1 = {83 ec 04 89 c2 c7 44 24 10 00 00 00 00 8d 45 f8 89 44 24 0c 89 54 24 08 a1 90 01 04 89 44 24 04 8b 45 fc 89 04 24 e8 90 01 04 83 ec 14 a1 90 01 04 89 04 24 e8 90 01 04 83 ec 04 89 c2 c7 44 24 10 00 00 00 00 8d 45 f8 89 44 24 0c 89 54 24 08 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}