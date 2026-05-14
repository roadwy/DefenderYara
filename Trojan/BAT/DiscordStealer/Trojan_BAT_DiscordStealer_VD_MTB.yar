
rule Trojan_BAT_DiscordStealer_VD_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 72 64 54 6f 6b 65 6e 47 72 61 62 62 65 72 2e 64 6c 6c } //5 DiscordTokenGrabber.dll
		$a_01_1 = {67 65 74 5f 54 6f 6b 65 6e } //1 get_Token
		$a_00_2 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 77 00 65 00 62 00 68 00 6f 00 6f 00 6b 00 73 00 2f 00 } //5 https://discord.com/api/webhooks/
		$a_00_3 = {5c 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 5c 00 6c 00 65 00 76 00 65 00 6c 00 64 00 62 00 } //1 \discord\Local Storage\leveldb
		$a_00_4 = {63 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 5f 00 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 64 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00 } //1 complete_system_data.txt
		$a_00_5 = {6d 00 66 00 61 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 38 00 30 00 2c 00 39 00 30 00 7d 00 } //1 mfa\.[\w-]{80,90}
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_00_2  & 1)*5+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=13
 
}