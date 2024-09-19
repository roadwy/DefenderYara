
rule Trojan_MacOS_RealstStealer_A_MTB{
	meta:
		description = "Trojan:MacOS/RealstStealer.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 50 72 6f 66 69 6c 65 20 2f 44 6f 77 6e 6c 6f 61 64 73 2f 63 61 63 68 65 64 5f 64 61 74 61 2f 64 61 74 61 2f 43 61 72 64 73 2e 74 78 74 } //1 /Profile /Downloads/cached_data/data/Cards.txt
		$a_00_1 = {64 61 74 61 2f 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 data/Passwords.txt
		$a_00_2 = {64 75 6d 70 2d 67 65 6e 65 72 69 63 2d 70 61 73 73 77 6f 72 64 73 } //1 dump-generic-passwords
		$a_00_3 = {6d 6f 64 75 6c 65 73 2f 64 61 74 61 5f 73 74 65 61 6c 65 72 73 } //1 modules/data_stealers
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}