
rule Trojan_Win32_UpperCider_A_dha{
	meta:
		description = "Trojan:Win32/UpperCider.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 c7 45 90 01 01 75 61 6c 50 c7 45 90 01 01 72 6f 74 65 90 02 02 c7 45 90 01 01 63 74 90 02 06 c7 45 90 01 01 6b 65 72 6e c7 45 90 01 01 65 6c 33 32 c7 45 90 01 01 2e 64 6c 6c 90 02 06 ff 15 90 01 04 50 ff 15 90 00 } //1
		$a_03_1 = {5e 8a 10 30 11 40 41 4e 75 90 01 01 4f 75 90 09 02 00 6a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}