
rule Trojan_Win64_DiscordRat_CQ_MTB{
	meta:
		description = "Trojan:Win64/DiscordRat.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 8a 04 13 41 80 f0 5a 44 88 04 01 48 ff c0 48 ff c2 48 39 d7 75 e9 } //1
		$a_81_1 = {4e 45 57 20 56 49 43 54 49 4d 20 44 45 54 45 43 54 45 44 } //1 NEW VICTIM DETECTED
		$a_81_2 = {77 69 66 69 5f 70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //1 wifi_passwords.txt
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}