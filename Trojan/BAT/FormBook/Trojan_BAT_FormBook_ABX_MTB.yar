
rule Trojan_BAT_FormBook_ABX_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {57 9d a2 29 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 7c 00 00 00 57 00 00 00 8f 02 00 00 ea 02 00 00 db 02 00 00 } //01 00 
		$a_01_1 = {53 68 6f 72 74 41 6e 64 4c 6f 6e 67 4b 65 79 77 6f 72 64 } //01 00  ShortAndLongKeyword
		$a_01_2 = {47 00 65 00 74 00 54 00 65 00 6d 00 70 00 46 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 } //01 00  GetTempFileName
		$a_01_3 = {48 00 48 00 4d 00 48 00 65 00 48 00 48 00 48 00 74 00 48 00 48 00 48 00 68 00 48 00 48 00 48 00 6f 00 48 00 48 00 48 00 64 00 48 00 48 00 30 00 48 00 48 00 } //00 00  HHMHeHHHtHHHhHHHoHHHdHH0HH
	condition:
		any of ($a_*)
 
}