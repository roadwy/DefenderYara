
rule Trojan_Win32_Guloader_BA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 68 65 69 6c 6f 73 74 6f 6d 61 74 61 2e 69 6e 69 } //2 cheilostomata.ini
		$a_81_1 = {63 68 72 69 73 74 69 6e 73 2e 61 6c 6b } //2 christins.alk
		$a_81_2 = {4a 65 6e 64 65 5c 72 61 61 6b 6f 73 74 } //2 Jende\raakost
		$a_81_3 = {72 68 65 73 75 73 70 6f 73 69 74 69 76 } //2 rhesuspositiv
		$a_81_4 = {54 65 6b 73 62 65 68 61 6e 64 6c 69 6e 67 73 66 61 63 69 6c 69 74 65 74 65 72 } //2 Teksbehandlingsfaciliteter
		$a_81_5 = {52 65 63 61 6e 74 73 5c 6b 69 72 73 65 62 72 73 74 65 6e } //2 Recants\kirsebrsten
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2) >=12
 
}