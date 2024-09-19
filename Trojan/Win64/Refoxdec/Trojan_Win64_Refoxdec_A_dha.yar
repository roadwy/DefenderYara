
rule Trojan_Win64_Refoxdec_A_dha{
	meta:
		description = "Trojan:Win64/Refoxdec.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 41 6c 6c 41 75 74 68 44 61 74 61 } //4 getAllAuthData
		$a_01_1 = {53 45 4c 45 43 54 20 65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 2c 20 65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 2c 20 68 6f 73 74 6e 61 6d 65 2c 68 74 74 70 52 65 61 6c 6d 20 46 52 4f 4d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //2 SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins
		$a_01_2 = {5c 73 69 67 6e 6f 6e 73 2e 73 71 6c 69 74 65 } //1 \signons.sqlite
		$a_01_3 = {5c 6c 6f 67 69 6e 73 2e 6a 73 6f 6e } //1 \logins.json
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}