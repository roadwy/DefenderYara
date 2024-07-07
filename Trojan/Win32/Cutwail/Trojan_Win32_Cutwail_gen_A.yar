
rule Trojan_Win32_Cutwail_gen_A{
	meta:
		description = "Trojan:Win32/Cutwail.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {6b d2 28 0f be 82 90 01 04 83 f8 30 7c 31 8b 8d 90 01 04 6b c9 28 90 09 1e 00 6a 19 e8 90 00 } //1
		$a_03_1 = {40 73 33 6a ff e8 90 01 04 83 c4 04 69 c0 0d 66 19 00 90 00 } //1
		$a_03_2 = {6b c9 28 81 c1 90 01 04 51 68 90 01 04 8d 95 90 01 04 52 ff 15 90 01 04 83 c4 10 eb 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}