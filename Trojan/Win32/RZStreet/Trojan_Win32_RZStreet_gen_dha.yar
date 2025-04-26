
rule Trojan_Win32_RZStreet_gen_dha{
	meta:
		description = "Trojan:Win32/RZStreet.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_43_0 = {be 14 10 33 ca 8b 85 90 01 04 03 85 90 01 04 88 08 90 00 05 } //5
		$a_10_1 = {ff 75 f8 ff 35 90 01 04 c3 6a 90 01 01 ff 15 90 00 00 00 5d 04 00 00 87 01 05 80 5c 28 00 00 88 01 05 80 00 00 01 00 08 00 12 00 ac 21 42 67 48 75 6e 74 65 72 2e 67 65 6e 21 64 68 61 00 00 01 40 05 82 } //4608
	condition:
		((#a_43_0  & 1)*5+(#a_10_1  & 1)*4608) >=10
 
}