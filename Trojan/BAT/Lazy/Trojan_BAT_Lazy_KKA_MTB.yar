
rule Trojan_BAT_Lazy_KKA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 07 00 00 "
		
	strings :
		$a_01_0 = {60 4e 49 47 45 52 2e } //20 `NIGER.
		$a_01_1 = {6c 6f 61 64 5f 61 70 70 5f 64 61 74 61 } //6 load_app_data
		$a_01_2 = {6c 6f 61 64 5f 75 73 65 72 5f 64 61 74 61 } //5 load_user_data
		$a_01_3 = {67 65 74 5f 44 69 73 63 6f 72 64 49 64 } //4 get_DiscordId
		$a_01_4 = {67 65 74 5f 44 69 73 63 6f 72 64 55 73 65 72 6e 61 6d 65 } //3 get_DiscordUsername
		$a_01_5 = {4c 69 6e 6b 44 69 73 63 6f 72 64 4d 61 6e 75 61 6c 6c 79 } //2 LinkDiscordManually
		$a_01_6 = {43 72 65 64 65 6e 74 69 61 6c 73 46 69 6c 65 } //1 CredentialsFile
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*6+(#a_01_2  & 1)*5+(#a_01_3  & 1)*4+(#a_01_4  & 1)*3+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=41
 
}