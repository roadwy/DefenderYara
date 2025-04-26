
rule Trojan_Win32_Floxif_AW_MTB{
	meta:
		description = "Trojan:Win32/Floxif.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 62 52 6f 62 6f 74 } //3 FbRobot
		$a_81_1 = {50 4b 31 31 53 44 52 5f 44 65 63 72 79 70 74 } //3 PK11SDR_Decrypt
		$a_81_2 = {2f 70 72 6f 66 69 6c 65 2e 70 68 70 3f 69 64 3d } //3 /profile.php?id=
		$a_81_3 = {7a 39 59 7a 62 78 35 4a 62 56 53 55 57 6d 54 68 } //3 z9Yzbx5JbVSUWmTh
		$a_81_4 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //3 encryptedPassword
		$a_81_5 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //3 encrypted_key
		$a_81_6 = {6f 73 5f 63 72 79 70 74 } //3 os_crypt
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}