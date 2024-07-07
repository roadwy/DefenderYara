
rule Trojan_WinNT_Slingshot_A_dha{
	meta:
		description = "Trojan:WinNT/Slingshot.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {bf 73 6e 6d 65 57 6a 18 51 ff 15 90 01 04 8b d8 85 db 75 09 c7 45 fc 9a 00 00 c0 90 00 } //2
		$a_03_1 = {7d 14 32 d2 8b ce 89 5e 18 ff 15 90 01 04 8b c3 e9 90 01 02 00 00 81 7f 0c 00 20 22 00 90 00 } //2
		$a_03_2 = {ff d5 85 c0 74 90 01 01 83 67 0c 00 83 27 00 89 47 08 53 ff 74 24 20 c7 00 58 89 04 24 90 00 } //2
		$a_80_3 = {5c 44 6f 73 44 65 76 69 63 65 73 5c 61 6d 78 70 63 69 } //\DosDevices\amxpci  1
		$a_80_4 = {5c 44 65 76 69 63 65 5c 61 6d 78 70 63 69 } //\Device\amxpci  1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}