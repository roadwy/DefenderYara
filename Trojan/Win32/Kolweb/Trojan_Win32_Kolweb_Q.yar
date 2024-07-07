
rule Trojan_Win32_Kolweb_Q{
	meta:
		description = "Trojan:Win32/Kolweb.Q,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 72 69 76 65 72 61 2e 64 6c 6c 20 64 72 69 76 65 72 61 2e 65 78 65 00 } //1
		$a_03_1 = {83 e8 10 74 90 01 01 83 e8 10 74 90 01 01 e9 90 01 02 00 00 33 c0 89 44 24 08 8d 44 24 08 50 68 7f 66 04 40 8b 46 28 50 e8 90 01 02 ff ff 8b d0 8b c6 e8 90 01 02 ff ff 66 c7 04 24 03 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}