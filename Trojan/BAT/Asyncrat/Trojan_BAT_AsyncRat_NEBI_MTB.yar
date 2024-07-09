
rule Trojan_BAT_AsyncRat_NEBI_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 06 6f ?? 00 00 0a 00 11 04 05 6f ?? 00 00 0a 00 11 04 0e 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 03 16 03 8e b7 6f ?? 00 00 0a 0b 11 04 6f ?? 00 00 0a 00 07 0c 2b 00 08 2a } //10
		$a_01_1 = {6d 64 35 44 65 63 72 79 70 74 } //2 md5Decrypt
		$a_01_2 = {73 65 74 5f 53 68 75 74 64 6f 77 6e 53 74 79 6c 65 } //2 set_ShutdownStyle
		$a_01_3 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 } //2 ProcessHacker
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}