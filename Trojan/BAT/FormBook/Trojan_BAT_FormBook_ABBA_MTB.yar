
rule Trojan_BAT_FormBook_ABBA_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_03_0 = {07 06 08 06 8e 69 5d 91 02 08 91 61 d2 6f 90 01 03 0a 08 17 58 0c 08 02 8e 69 3f 90 01 03 ff 07 2a 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_2 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_3 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}