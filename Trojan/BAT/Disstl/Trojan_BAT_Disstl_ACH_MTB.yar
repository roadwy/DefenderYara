
rule Trojan_BAT_Disstl_ACH_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 09 00 00 "
		
	strings :
		$a_80_0 = {5c 44 69 73 63 6f 72 64 } //\Discord  3
		$a_80_1 = {5c 64 69 73 63 6f 72 64 63 61 6e 61 72 79 } //\discordcanary  3
		$a_80_2 = {5c 64 69 73 63 6f 72 64 70 74 62 } //\discordptb  3
		$a_80_3 = {5b 5c 77 2d 5d 7b 32 34 7d 5c 2e 5b 5c 77 2d 5d 7b 36 7d 5c 2e 5b 5c 77 2d 5d 7b 32 37 7d } //[\w-]{24}\.[\w-]{6}\.[\w-]{27}  2
		$a_80_4 = {6d 66 61 5c 2e 5b 5c 77 2d 5d 7b 38 34 7d } //mfa\.[\w-]{84}  2
		$a_80_5 = {50 6f 73 74 54 6f 6b 65 6e } //PostToken  2
		$a_80_6 = {68 74 74 70 43 6c 69 65 6e 74 } //httpClient  2
		$a_80_7 = {5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //\Local Storage\leveldb  2
		$a_80_8 = {44 69 73 63 6f 72 64 20 54 6f 6b 65 6e 20 47 72 61 62 62 65 72 } //Discord Token Grabber  2
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2) >=21
 
}