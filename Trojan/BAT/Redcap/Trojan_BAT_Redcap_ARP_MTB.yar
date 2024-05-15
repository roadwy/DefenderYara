
rule Trojan_BAT_Redcap_ARP_MTB{
	meta:
		description = "Trojan:BAT/Redcap.ARP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 61 72 63 2e 6d 65 2f 36 36 65 37 36 38 38 39 2d 63 64 66 36 2d 34 37 39 35 2d 61 37 31 63 2d 32 33 32 33 38 61 33 62 32 62 35 31 } //01 00  searc.me/66e76889-cdf6-4795-a71c-23238a3b2b51
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 } //01 00  SOFTWARE\Policies\Google\Chrome
		$a_01_2 = {50 72 6f 6d 70 74 46 6f 72 50 61 73 73 77 6f 72 64 } //01 00  PromptForPassword
		$a_01_3 = {49 4e 43 4f 52 52 45 43 54 5f 50 41 53 53 57 4f 52 44 } //01 00  INCORRECT_PASSWORD
		$a_01_4 = {52 45 51 55 45 53 54 5f 41 44 4d 49 4e 49 53 54 52 41 54 4f 52 } //01 00  REQUEST_ADMINISTRATOR
		$a_01_5 = {52 45 51 55 49 52 45 5f 53 4d 41 52 54 43 41 52 44 } //01 00  REQUIRE_SMARTCARD
		$a_01_6 = {4b 45 45 50 5f 55 53 45 52 4e 41 4d 45 } //00 00  KEEP_USERNAME
	condition:
		any of ($a_*)
 
}