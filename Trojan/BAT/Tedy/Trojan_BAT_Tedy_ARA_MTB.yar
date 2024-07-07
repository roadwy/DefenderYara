
rule Trojan_BAT_Tedy_ARA_MTB{
	meta:
		description = "Trojan:BAT/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 91 0d 06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 0b 08 17 59 0c 07 08 32 e5 } //2
		$a_01_1 = {45 68 6a 69 6f 67 65 72 } //2 Ehjioger
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_Tedy_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/Tedy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {4b 65 79 6c 6f 67 67 65 72 20 73 74 61 72 74 65 64 2c 20 73 65 65 20 6b 65 79 6c 6f 67 67 73 20 61 74 20 68 74 74 70 3a 2f 2f 7b 76 69 63 69 74 6d 20 49 50 7d 3a 38 30 38 30 2f 6b 65 79 6c 6f 67 67 65 72 2f 6b 65 79 6c 6f 67 67 2e 74 78 74 } //Keylogger started, see keyloggs at http://{vicitm IP}:8080/keylogger/keylogg.txt  2
		$a_80_1 = {5c 72 61 6e 73 6f 6d 77 61 72 65 2e 62 61 74 } //\ransomware.bat  2
		$a_80_2 = {5c 6f 75 74 70 75 74 5f 66 69 72 65 66 6f 78 2e 74 78 74 } //\output_firefox.txt  2
		$a_80_3 = {55 73 61 67 65 3a 20 73 74 65 61 6c 5f 70 77 64 20 3c 66 69 72 65 66 6f 78 2f 67 6f 6f 67 6c 65 3e } //Usage: steal_pwd <firefox/google>  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}