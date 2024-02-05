
rule Trojan_BAT_Redline_GIF_MTB{
	meta:
		description = "Trojan:BAT/Redline.GIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 68 75 66 66 65 64 2e 65 78 65 } //Chuffed.exe  01 00 
		$a_80_1 = {44 6a 73 56 58 43 4d 59 4a 46 77 35 49 48 63 57 50 43 6b 49 42 79 38 55 4f 55 55 4e 4b 7a 64 66 49 54 4e 63 55 77 3d 3d } //DjsVXCMYJFw5IHcWPCkIBy8UOUUNKzdfITNcUw==  01 00 
		$a_80_2 = {49 53 67 65 41 44 55 6a 58 46 4d 3d } //ISgeADUjXFM=  01 00 
		$a_01_3 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //01 00 
		$a_80_4 = {25 44 53 4b 5f 32 33 25 63 6f 6f 6b 69 65 73 } //%DSK_23%cookies  01 00 
		$a_80_5 = {73 65 74 74 53 74 72 69 6e 67 2e 52 65 70 6c 61 63 65 69 6e 67 5b 40 6e 61 6d 65 3d 5c 55 53 74 72 69 6e 67 2e 52 65 70 6c 61 63 65 73 65 72 6e 61 6d 65 5c 5d 2f 76 61 53 74 72 69 6e 67 2e 52 65 70 6c 61 63 65 6c 75 65 6d 6f 7a 5f 63 6f 6f 6b 69 65 73 } //settString.Replaceing[@name=\UString.Replacesername\]/vaString.Replaceluemoz_cookies  01 00 
		$a_80_6 = {4e 6f 72 64 56 70 6e 2e 65 78 65 2a 4e 6f 47 65 74 44 69 72 65 63 74 6f 72 69 65 73 72 64 } //NordVpn.exe*NoGetDirectoriesrd  01 00 
		$a_80_7 = {6e 65 74 2e 74 63 70 3a 2f 2f } //net.tcp://  00 00 
	condition:
		any of ($a_*)
 
}