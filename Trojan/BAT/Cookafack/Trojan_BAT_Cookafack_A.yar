
rule Trojan_BAT_Cookafack_A{
	meta:
		description = "Trojan:BAT/Cookafack.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 45 00 6e 00 74 00 65 00 72 00 20 00 41 00 20 00 79 00 6f 00 75 00 72 00 20 00 65 00 6d 00 61 00 69 00 6c 00 20 00 61 00 6e 00 64 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 Please Enter A your email and Password
		$a_01_1 = {66 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 5f 00 68 00 61 00 63 00 6b 00 65 00 72 00 5f 00 76 00 } //1 facebook_hacker_v
		$a_01_2 = {66 61 63 65 62 6f 6f 6b 20 68 61 63 6b 65 72 20 76 } //1 facebook hacker v
		$a_01_3 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 68 00 61 00 63 00 6b 00 65 00 64 00 20 00 62 00 79 00 20 00 79 00 6f 00 75 00 } //1 password will be hacked by you
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}