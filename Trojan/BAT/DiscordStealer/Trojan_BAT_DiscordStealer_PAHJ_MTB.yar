
rule Trojan_BAT_DiscordStealer_PAHJ_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.PAHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 6c 00 65 00 76 00 65 00 6c 00 64 00 62 00 } //2 \Google\Chrome\User Data\Default\Local Storage\leveldb
		$a_00_1 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 76 00 39 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 40 00 6d 00 65 00 } //1 discord.com/api/v9/users/@me
		$a_01_2 = {53 63 61 6e 42 72 6f 77 73 65 72 73 } //2 ScanBrowsers
		$a_01_3 = {47 65 74 55 73 65 72 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 GetUserInformation
		$a_01_4 = {47 65 74 42 69 6c 6c 69 6e 67 49 6e 66 6f } //1 GetBillingInfo
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}