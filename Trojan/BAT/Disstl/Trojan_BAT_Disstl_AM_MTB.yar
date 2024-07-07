
rule Trojan_BAT_Disstl_AM_MTB{
	meta:
		description = "Trojan:BAT/Disstl.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 07 00 00 "
		
	strings :
		$a_00_0 = {0b 07 6f 3c 00 00 0a 1f 3b 2e 0c 07 6f 3c 00 00 0a 1f 58 fe 01 2b 01 } //10
		$a_80_1 = {64 69 73 63 6f 72 64 5f 6d 6f 64 75 6c 65 73 } //discord_modules  3
		$a_80_2 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 1 & Del  3
		$a_80_3 = {62 64 6c 65 76 65 6c 5c 65 67 61 72 6f 74 53 20 6c 61 63 6f 4c 5c 64 72 6f 63 73 69 64 } //bdlevel\egarotS lacoL\drocsid  3
		$a_80_4 = {62 64 6c 65 76 65 6c 5c 65 67 61 72 6f 74 53 20 6c 61 63 6f 4c 5c 62 74 70 64 72 6f 63 73 69 64 } //bdlevel\egarotS lacoL\btpdrocsid  3
		$a_80_5 = {6c 72 75 5f 72 61 74 61 76 61 } //lru_ratava  3
		$a_80_6 = {50 6f 73 74 41 73 79 6e 63 } //PostAsync  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=28
 
}
rule Trojan_BAT_Disstl_AM_MTB_2{
	meta:
		description = "Trojan:BAT/Disstl.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {47 00 72 00 61 00 6e 00 64 00 6f 00 20 00 2a 00 6b 00 69 00 73 00 73 00 65 00 73 00 20 00 79 00 6f 00 75 00 20 00 6f 00 6e 00 20 00 74 00 68 00 65 00 20 00 63 00 68 00 65 00 65 00 6b 00 2a 00 } //1 Grando *kisses you on the cheek*
		$a_01_1 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_2 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 70 00 69 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 40 00 6d 00 65 00 } //1 discord.com/api/users/@me
		$a_01_3 = {69 00 63 00 61 00 6e 00 68 00 61 00 7a 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 icanhazip.com
		$a_01_4 = {66 00 69 00 64 00 64 00 6c 00 65 00 72 00 } //1 fiddler
		$a_01_5 = {68 00 74 00 74 00 70 00 64 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 75 00 69 00 } //1 httpdebuggerui
		$a_01_6 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}