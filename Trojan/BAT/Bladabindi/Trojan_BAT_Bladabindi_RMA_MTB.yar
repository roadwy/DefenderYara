
rule Trojan_BAT_Bladabindi_RMA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {67 65 74 5f 4c 6f 67 69 6e 42 74 6e } //01 00  get_LoginBtn
		$a_81_1 = {67 65 74 5f 41 64 64 50 61 73 73 77 6f 72 64 62 74 6e } //01 00  get_AddPasswordbtn
		$a_81_2 = {50 61 73 73 77 6f 72 64 4c 69 73 74 } //01 00  PasswordList
		$a_81_3 = {43 68 65 63 6b 50 61 73 73 77 6f 72 64 6c 62 6c } //01 00  CheckPasswordlbl
		$a_81_4 = {43 72 65 61 74 65 55 73 65 72 4e 61 6d 65 6c 62 6c } //0a 00  CreateUserNamelbl
		$a_81_5 = {24 62 37 65 66 37 30 33 62 2d 37 63 33 61 2d 34 34 62 64 2d 61 37 64 33 2d 35 32 38 31 30 64 66 37 64 32 37 38 } //0a 00  $b7ef703b-7c3a-44bd-a7d3-52810df7d278
		$a_81_6 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 50 61 73 73 20 56 61 75 6c 74 5c 41 63 63 6f 75 6e 74 50 61 73 73 77 6f 72 64 } //0a 00  \Documents\Pass Vault\AccountPassword
		$a_81_7 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 50 61 73 73 20 56 61 75 6c 74 5c 4b 65 79 73 2e 74 78 74 } //0a 00  \Documents\Pass Vault\Keys.txt
		$a_81_8 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 50 61 73 73 20 56 61 75 6c 74 5c 4b 65 79 73 44 65 63 72 79 70 74 65 64 2e 74 78 74 } //00 00  \Documents\Pass Vault\KeysDecrypted.txt
	condition:
		any of ($a_*)
 
}