
rule Trojan_Win32_Qhost_FY{
	meta:
		description = "Trojan:Win32/Qhost.FY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 02 8d 45 90 01 01 b9 90 01 03 00 8b 55 90 01 01 e8 90 01 04 8b 45 90 1b 00 e8 90 01 04 50 e8 90 00 } //1
		$a_00_1 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 ee 73 74 73 00 } //1
		$a_02_2 = {76 6b 6f 6e 74 61 6b 74 65 2e 72 75 90 05 10 01 00 ff ff ff ff 90 01 04 90 05 0f 04 30 2d 39 2e 90 02 30 90 1b 03 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}