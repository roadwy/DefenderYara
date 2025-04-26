
rule Trojan_Win32_Vidar_AA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,50 00 50 00 08 00 00 "
		
	strings :
		$a_80_0 = {5c 4d 6f 7a 69 6c 6c 61 5c 69 63 65 63 61 74 5c 50 72 6f 66 69 6c 65 73 5c } //\Mozilla\icecat\Profiles\  10
		$a_80_1 = {5c 4e 45 54 47 41 54 45 20 54 65 63 68 6e 6f 6c 6f 67 69 65 73 5c 42 6c 61 63 6b 48 61 77 6b 5c 50 72 6f 66 69 6c 65 73 5c } //\NETGATE Technologies\BlackHawk\Profiles\  10
		$a_80_2 = {5c 54 6f 72 42 72 6f 5c 50 72 6f 66 69 6c 65 } //\TorBro\Profile  10
		$a_80_3 = {5c 43 6f 6d 6f 64 6f 5c 44 72 61 67 6f 6e 5c 55 73 65 72 20 44 61 74 61 } //\Comodo\Dragon\User Data  10
		$a_80_4 = {5c 43 68 72 6f 6d 69 75 6d 5c 55 73 65 72 20 44 61 74 61 } //\Chromium\User Data  10
		$a_80_5 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //passwords.txt  10
		$a_80_6 = {65 6e 63 72 79 70 74 65 64 55 73 65 72 6e 61 6d 65 } //encryptedUsername  10
		$a_80_7 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //encryptedPassword  10
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*10+(#a_80_3  & 1)*10+(#a_80_4  & 1)*10+(#a_80_5  & 1)*10+(#a_80_6  & 1)*10+(#a_80_7  & 1)*10) >=80
 
}