
rule Backdoor_BAT_Blacknet_GG_MTB{
	meta:
		description = "Backdoor:BAT/Blacknet.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 10 00 00 "
		
	strings :
		$a_81_0 = {42 6c 61 63 6b 4e 45 54 } //10 BlackNET
		$a_80_1 = {53 74 61 72 74 4b 65 79 6c 6f 67 67 65 72 } //StartKeylogger  1
		$a_80_2 = {53 70 61 6d 45 6d 61 69 6c } //SpamEmail  1
		$a_80_3 = {41 74 74 61 63 6b } //Attack  1
		$a_80_4 = {42 69 74 63 6f 69 6e } //Bitcoin  1
		$a_80_5 = {77 61 6c 6c 65 74 } //wallet  1
		$a_80_6 = {63 6c 69 65 6e 74 69 64 3d } //clientid=  1
		$a_80_7 = {73 63 68 74 61 73 6b 73 } //schtasks  1
		$a_80_8 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //SELECT * FROM AntivirusProduct  1
		$a_80_9 = {2f 63 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e } ///c ping 1.1.1.1 -n  1
		$a_80_10 = {72 65 6d 6f 74 65 73 68 65 6c 6c 2e 70 68 70 } //remoteshell.php  1
		$a_80_11 = {67 65 74 43 6f 6d 6d 61 6e 64 2e 70 68 70 3f 69 64 3d } //getCommand.php?id=  1
		$a_80_12 = {72 65 63 65 69 76 65 2e 70 68 70 3f 63 6f 6d 6d 61 6e 64 3d } //receive.php?command=  1
		$a_80_13 = {2f 75 70 6c 6f 61 64 2e 70 68 70 3f 69 64 3d } ///upload.php?id=  1
		$a_80_14 = {2f 63 68 65 63 6b 5f 70 61 6e 65 6c 2e 70 68 70 } ///check_panel.php  1
		$a_80_15 = {63 6f 6e 6e 65 63 74 69 6f 6e 2e 70 68 70 } //connection.php  1
	condition:
		((#a_81_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1) >=20
 
}