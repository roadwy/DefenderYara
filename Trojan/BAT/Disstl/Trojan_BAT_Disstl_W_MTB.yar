
rule Trojan_BAT_Disstl_W_MTB{
	meta:
		description = "Trojan:BAT/Disstl.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {50 69 74 46 75 63 6b 65 72 56 31 } //PitFuckerV1  3
		$a_80_1 = {64 69 73 63 6f 72 64 61 70 70 } //discordapp  3
		$a_80_2 = {5b 4f 77 6e 65 72 5d 20 50 61 74 50 } //[Owner] PatP  3
		$a_80_3 = {47 65 74 52 6f 6f 74 } //GetRoot  3
		$a_80_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  3
		$a_80_5 = {61 76 61 74 61 72 5f 75 72 6c } //avatar_url  3
		$a_80_6 = {53 65 6e 64 4d 65 52 65 73 75 6c 74 73 } //SendMeResults  3
		$a_80_7 = {44 61 74 61 47 72 61 62 42 75 74 74 6f 6e } //DataGrabButton  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}