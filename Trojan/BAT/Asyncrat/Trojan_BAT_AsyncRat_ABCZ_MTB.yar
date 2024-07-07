
rule Trojan_BAT_AsyncRat_ABCZ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ABCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 08 07 6f 90 01 03 0a 08 18 6f 90 01 03 0a 08 6f 90 01 03 0a 02 50 16 02 50 8e 69 6f 90 01 03 0a 2a 90 00 } //3
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_2 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_3 = {72 00 5a 00 4c 00 54 00 59 00 6e 00 61 00 47 00 46 00 4a 00 62 00 59 00 51 00 44 00 79 00 6f 00 4d 00 58 00 5a 00 6d 00 57 00 50 00 53 00 66 00 64 00 53 00 4b 00 44 00 4e 00 74 00 70 00 41 00 50 00 51 00 65 00 45 00 77 00 58 00 42 00 4b 00 } //1 rZLTYnaGFJbYQDyoMXZmWPSfdSKDNtpAPQeEwXBK
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}