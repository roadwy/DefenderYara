
rule Trojan_Win32_Brackash_A{
	meta:
		description = "Trojan:Win32/Brackash.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {6d 65 6d 6f 72 79 90 02 0c 6c 69 6b 65 90 02 0c 6c 6f 76 65 90 00 } //1
		$a_02_1 = {74 61 73 6b 90 05 04 01 00 ff ff ff ff 05 00 00 00 69 65 78 70 6c 90 05 04 01 00 ff ff ff ff 03 00 00 00 6d 67 72 90 05 04 01 00 ff ff ff ff 03 00 00 00 6f 72 65 90 05 04 01 00 ff ff ff ff 04 00 00 00 2e 65 78 65 00 90 00 } //1
		$a_03_2 = {74 0d 53 56 68 f4 05 00 00 50 e8 90 01 02 ff ff a1 90 00 } //1
		$a_03_3 = {ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 8b 06 e8 90 01 03 ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}