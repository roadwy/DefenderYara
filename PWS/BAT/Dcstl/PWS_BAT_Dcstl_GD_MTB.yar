
rule PWS_BAT_Dcstl_GD_MTB{
	meta:
		description = "PWS:BAT/Dcstl.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_80_0 = {5c 64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 5c } //\discord\Local Storage\leveldb\  10
		$a_80_1 = {44 69 73 63 6f 72 64 54 6f 6b 65 65 6e 20 62 79 20 4e 59 41 4e 20 43 41 54 } //DiscordTokeen by NYAN CAT  1
		$a_80_2 = {53 6d 74 70 44 65 6c 69 76 65 72 79 4d 65 74 68 6f 64 } //SmtpDeliveryMethod  1
		$a_80_3 = {68 74 74 70 73 3a 2f 2f 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 2f } //https://discordapp.com/api/webhooks/  1
		$a_80_4 = {22 28 5b 41 2d 5a 61 2d 7a 30 2d 39 5f 5c 2e 2f 5c 5c 2d 5d 29 7b 35 39 7d 22 } //"([A-Za-z0-9_\./\\-]){59}"  1
		$a_80_5 = {5b 5c 77 2d 5d 7b 32 34 7d 5c 2e 5b 5c 77 2d 5d 7b 36 7d 5c 2e 5b 5c 77 2d 5d 7b 32 37 7d } //[\w-]{24}\.[\w-]{6}\.[\w-]{27}  1
		$a_80_6 = {6d 66 61 5c 2e 5b 5c 77 2d 5d 7b 38 34 7d } //mfa\.[\w-]{84}  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=12
 
}