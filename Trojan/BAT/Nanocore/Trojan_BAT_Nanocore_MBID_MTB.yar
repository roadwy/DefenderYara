
rule Trojan_BAT_Nanocore_MBID_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.MBID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 41 00 41 00 45 00 4b 00 39 00 4b 00 41 00 41 00 67 00 41 00 41 00 42 00 43 00 76 00 55 00 67 00 41 00 4d 00 41 00 41 00 41 00 51 00 72 00 31 00 67 00 41 00 41 00 41 00 42 00 4d 00 77 00 41 00 51 00 } //1 AAAEK9KAAgAABCvUgAMAAAQr1gAAABMwAQ
		$a_01_1 = {47 00 53 00 30 00 4b 00 4a 00 67 00 77 00 72 00 55 00 51 00 6f 00 72 00 35 00 67 00 73 00 72 00 37 00 52 00 4d 00 47 00 4b 00 2f 00 4d 00 48 00 43 00 4a 00 70 00 30 00 71 00 77 00 41 00 } //1 GS0KJgwrUQor5gsr7RMGK/MHCJp0qwA
		$a_01_2 = {fa 25 33 00 16 00 00 01 00 00 00 0b 00 00 00 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}