
rule Trojan_Win32_Arefty_A{
	meta:
		description = "Trojan:Win32/Arefty.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 21 6a 01 53 ff 15 90 01 04 85 c0 74 0d ff b5 90 01 02 ff ff ff d0 90 00 } //1
		$a_03_1 = {3a 00 c7 45 90 01 01 5c 00 5f 00 c7 45 90 01 01 52 00 4d 00 c7 45 90 01 01 5f 00 00 00 85 c9 74 90 01 01 66 8b 01 6a 00 6a 00 6a 03 6a 00 6a 02 66 89 90 01 01 ec 8d 45 90 01 01 68 00 00 00 80 50 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}