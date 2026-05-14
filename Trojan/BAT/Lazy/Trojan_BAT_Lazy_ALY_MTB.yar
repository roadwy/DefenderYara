
rule Trojan_BAT_Lazy_ALY_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 28 07 08 9a 0d 09 6f 85 00 00 0a 1c 33 17 09 6f 86 00 00 0a 17 33 0e 09 6f 87 00 00 0a 6f 1e 00 00 0a 0a 2b 0a 08 17 58 0c 08 07 8e 69 32 d2 } //2
		$a_01_1 = {4d 65 72 74 5c 44 65 73 6b 74 6f 70 5c 44 69 73 63 6f 72 64 54 65 6c 65 67 72 61 6d 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 44 69 73 63 6f 72 64 54 65 6c 65 67 72 61 6d 2e 70 64 62 } //1 Mert\Desktop\DiscordTelegram\obj\Release\DiscordTelegram.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Lazy_ALY_MTB_2{
	meta:
		description = "Trojan:BAT/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 08 13 04 16 13 05 2b 24 11 04 11 05 6f ?? ?? ?? 0a 13 06 09 12 06 28 ?? ?? ?? 0a 72 9a 12 00 70 28 ?? ?? ?? 0a 0d 11 05 17 58 13 05 11 05 11 04 6f ?? ?? ?? 0a 32 d1 09 09 6f ?? ?? ?? 0a 17 59 17 } //2
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 69 00 73 00 20 00 6e 00 6f 00 77 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 69 00 6e 00 20 00 74 00 68 00 65 00 20 00 62 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 20 00 6f 00 66 00 20 00 74 00 68 00 69 00 73 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 } //1 Windows Logger is now running in the background of this system
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Lazy_ALY_MTB_3{
	meta:
		description = "Trojan:BAT/Lazy.ALY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0f 00 00 "
		
	strings :
		$a_01_0 = {41 4d 49 44 34 33 32 35 36 36 31 2d 39 38 45 35 2d 38 35 43 35 2d 33 37 33 36 2d 39 30 38 38 45 42 46 42 32 42 30 31 } //1 AMID4325661-98E5-85C5-3736-9088EBFB2B01
		$a_01_1 = {5b 44 59 4e 50 52 4f 50 53 5d 20 69 6e 73 74 61 6e 63 65 20 6f 66 20 57 69 6e 33 32 5f 42 49 4f 53 } //1 [DYNPROPS] instance of Win32_BIOS
		$a_01_2 = {52 65 6d 6f 76 65 2d 49 74 65 6d 20 24 6d 6f 66 50 61 74 68 20 2d 46 6f 72 63 65 } //1 Remove-Item $mofPath -Force
		$a_01_3 = {53 65 6c 66 2d 64 65 6c 65 74 65 20 45 58 45 20 61 66 74 65 72 20 63 6f 6d 70 6c 65 74 69 6f 6e } //1 Self-delete EXE after completion
		$a_01_4 = {44 4f 5f 4e 4f 54 5f 50 45 52 53 49 53 54 } //1 DO_NOT_PERSIST
		$a_01_5 = {52 45 51 55 45 53 54 5f 41 44 4d 49 4e 49 53 54 52 41 54 4f 52 } //1 REQUEST_ADMINISTRATOR
		$a_01_6 = {45 58 43 4c 55 44 45 5f 43 45 52 54 49 46 49 43 41 54 45 53 } //1 EXCLUDE_CERTIFICATES
		$a_01_7 = {52 45 51 55 49 52 45 5f 43 45 52 54 49 46 49 43 41 54 45 } //1 REQUIRE_CERTIFICATE
		$a_01_8 = {53 48 4f 57 5f 53 41 56 45 5f 43 48 45 43 4b 5f 42 4f 58 } //1 SHOW_SAVE_CHECK_BOX
		$a_01_9 = {52 45 51 55 49 52 45 5f 53 4d 41 52 54 43 41 52 44 } //1 REQUIRE_SMARTCARD
		$a_01_10 = {56 41 4c 49 44 41 54 45 5f 55 53 45 52 4e 41 4d 45 } //1 VALIDATE_USERNAME
		$a_01_11 = {43 4f 4d 50 4c 45 54 45 5f 55 53 45 52 4e 41 4d 45 } //1 COMPLETE_USERNAME
		$a_01_12 = {6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 2e 00 70 00 73 00 31 00 } //1 network.ps1
		$a_01_13 = {43 00 6c 00 69 00 63 00 6b 00 20 00 4f 00 4b 00 20 00 74 00 6f 00 20 00 65 00 78 00 69 00 74 00 } //1 Click OK to exit
		$a_01_14 = {72 00 61 00 6a 00 6b 00 75 00 6d 00 61 00 72 00 28 00 72 00 6a 00 29 00 2e 00 65 00 78 00 65 00 } //3 rajkumar(rj).exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*3) >=17
 
}