
rule Trojan_Win32_Redsacm_A{
	meta:
		description = "Trojan:Win32/Redsacm.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 72 69 76 65 72 50 72 6f 63 90 02 04 5c 6d 73 61 63 6d 33 32 2e 64 72 76 90 00 } //1
		$a_03_1 = {40 3b c6 72 f4 90 09 07 00 80 b0 90 01 02 b8 72 90 00 } //1
		$a_03_2 = {eb 14 68 88 13 00 00 ff 15 90 01 04 eb 07 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}