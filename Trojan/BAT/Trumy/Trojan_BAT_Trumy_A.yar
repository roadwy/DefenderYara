
rule Trojan_BAT_Trumy_A{
	meta:
		description = "Trojan:BAT/Trumy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {2f 70 72 6f 67 72 61 6d 2e 70 68 70 } ///program.php  1
		$a_80_1 = {67 65 74 3d 70 72 65 66 65 72 65 6e 63 65 73 } //get=preferences  1
		$a_80_2 = {5c 41 64 6f 62 65 20 46 6c 61 73 68 20 50 6c 61 79 65 72 2e 65 78 65 } //\Adobe Flash Player.exe  1
		$a_80_3 = {65 6b 6c 65 6e 74 69 } //eklenti  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule Trojan_BAT_Trumy_A_2{
	meta:
		description = "Trojan:BAT/Trumy.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {2f 70 72 6f 67 72 61 6d 2e 70 68 70 } ///program.php  1
		$a_80_1 = {67 65 74 3d 63 68 72 6f 6d 65 } //get=chrome  1
		$a_80_2 = {5c 63 68 72 6f 6d 65 2e 64 6c 6c } //\chrome.dll  1
		$a_80_3 = {65 6b 6c 65 6e 74 69 } //eklenti  1
		$a_80_4 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c } //\Google\Chrome\User Data\  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}