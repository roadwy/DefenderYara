
rule Trojan_Win32_FormBook_AQ_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 02 ff 45 90 01 01 ff 45 90 01 01 41 81 7d 90 02 10 90 13 8a 01 34 90 01 01 88 45 90 01 01 8b 55 90 01 01 8a 45 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_FormBook_AQ_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c1 99 6a 0c 5f f7 ff 8b 7d 10 8a 82 90 02 04 30 04 39 41 3b cb 72 90 00 } //1
		$a_01_1 = {83 c4 24 6a 40 68 00 30 00 00 53 56 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}