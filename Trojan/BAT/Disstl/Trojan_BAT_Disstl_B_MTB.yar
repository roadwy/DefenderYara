
rule Trojan_BAT_Disstl_B_MTB{
	meta:
		description = "Trojan:BAT/Disstl.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {5b 5c 77 2d 5d 7b 32 34 7d 5c 2e 5b 5c 77 2d 5d 7b 36 7d 5c 2e 5b 5c 77 2d 5d 7b 32 37 7d } //[\w-]{24}\.[\w-]{6}\.[\w-]{27}  3
		$a_80_1 = {6d 66 61 5c 2e 5b 5c 77 2d 5d 7b 38 34 7d } //mfa\.[\w-]{84}  3
		$a_80_2 = {44 69 73 63 6f 72 64 20 43 6c 69 6d 61 78 20 47 72 61 62 62 65 72 } //Discord Climax Grabber  3
		$a_80_3 = {57 65 44 65 6d 42 6f 79 7a } //WeDemBoyz  3
		$a_80_4 = {5c 44 69 73 63 6f 72 64 } //\Discord  3
		$a_80_5 = {5c 64 69 73 63 6f 72 64 63 61 6e 61 72 79 } //\discordcanary  3
		$a_80_6 = {46 6f 72 6d 55 72 6c 45 6e 63 6f 64 65 64 43 6f 6e 74 65 6e 74 } //FormUrlEncodedContent  3
		$a_80_7 = {50 6f 73 74 41 73 79 6e 63 } //PostAsync  3
		$a_80_8 = {61 76 61 74 61 72 55 72 6c } //avatarUrl  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}
rule Trojan_BAT_Disstl_B_MTB_2{
	meta:
		description = "Trojan:BAT/Disstl.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_00_0 = {1f 3b 2e 0c 08 6f 2d 00 00 0a 1f 58 fe 01 2b 01 17 0d 09 2c 05 08 13 04 de 29 00 06 } //10
		$a_80_1 = {44 69 73 63 6f 72 64 20 54 6f 6b 65 6e 20 47 72 61 62 62 65 72 } //Discord Token Grabber  3
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  3
		$a_80_3 = {61 76 61 74 61 72 5f 75 72 6c } //avatar_url  3
		$a_80_4 = {64 69 73 63 6f 72 64 70 74 62 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //discordptb\Local Storage\leveldb  3
		$a_80_5 = {64 69 73 63 6f 72 64 5c 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //discord\Local Storage\leveldb  3
		$a_80_6 = {52 65 6d 6f 76 65 41 63 63 65 73 73 52 75 6c 65 } //RemoveAccessRule  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=28
 
}