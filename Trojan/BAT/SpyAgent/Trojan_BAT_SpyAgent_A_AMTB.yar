
rule Trojan_BAT_SpyAgent_A_AMTB{
	meta:
		description = "Trojan:BAT/SpyAgent.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 74 68 72 6f 77 66 72 65 65 2e 63 6f 6d 2f 61 75 74 68 } //https://throwfree.com/auth  1
		$a_80_1 = {6d 61 6b 65 50 6f 73 74 } //makePost  1
		$a_80_2 = {47 65 74 55 73 65 72 73 49 6e 66 6f } //GetUsersInfo  1
		$a_80_3 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //ProcessStartInfo  1
		$a_80_4 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 55 73 65 72 41 63 63 6f 75 6e 74 20 57 48 45 52 45 20 53 74 61 74 75 73 3d 27 4f 4b 27 } //SELECT * FROM Win32_UserAccount WHERE Status='OK'  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}