
rule Trojan_Win32_Filecoder_ARA_MTB{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {51 52 8b 4d 08 8b 55 0c 81 31 90 01 04 f7 11 83 c1 04 4a 75 f2 5a 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Filecoder_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 46 43 56 64 44 6f 64 44 65 69 57 78 4c 44 4e 44 58 } //SOFTWARE\FCVdDodDeiWxLDNDX  02 00 
		$a_80_1 = {52 45 43 4f 56 45 52 } //RECOVER  02 00 
		$a_80_2 = {64 6f 6c 6c 61 72 73 20 69 6e 20 42 69 74 63 6f 69 6e } //dollars in Bitcoin  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Filecoder_ARA_MTB_3{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 52 52 61 6e 73 6f 6d } //02 00  SOFTWARE\RRansom
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 69 70 6c 6f 67 67 65 72 2e 63 6f 6d 2f } //02 00  https://iplogger.com/
		$a_80_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 53 79 73 74 65 6d 52 65 73 74 6f 72 65 } //SELECT * FROM SystemRestore  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Filecoder_ARA_MTB_4{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 69 67 43 61 73 68 46 6f 72 59 6f 75 2e 65 78 65 } //02 00  BigCashForYou.exe
		$a_01_1 = {49 66 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 6b 6e 6f 77 20 6d 6f 72 65 20 6c 6f 6f 6b 20 61 74 20 74 68 65 20 61 74 74 61 63 68 6d 65 6e 74 21 } //02 00  If you want to know more look at the attachment!
		$a_01_2 = {52 61 6e 73 6f 6d 57 61 72 5f 45 4f 46 } //00 00  RansomWar_EOF
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Filecoder_ARA_MTB_5{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {41 74 20 74 68 65 20 6d 6f 6d 65 6e 74 2c 20 79 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 6e 6f 74 20 70 72 6f 74 65 63 74 65 64 2e } //02 00  At the moment, your system is not protected.
		$a_01_1 = {54 6f 20 67 65 74 20 73 74 61 72 74 65 64 2c 20 73 65 6e 64 20 61 20 66 69 6c 65 20 74 6f 20 64 65 63 72 79 70 74 20 74 72 69 61 6c 2e } //02 00  To get started, send a file to decrypt trial.
		$a_80_2 = {74 43 72 79 70 74 6f 50 50 20 52 4e 47 } //tCryptoPP RNG  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Filecoder_ARA_MTB_6{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_80_0 = {41 6c 6c 20 59 6f 75 72 20 46 69 6c 65 73 20 45 6e 63 72 79 70 74 65 64 } //All Your Files Encrypted  02 00 
		$a_80_1 = {58 69 6e 66 65 63 74 65 72 2e 65 78 65 } //Xinfecter.exe  02 00 
		$a_80_2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f } //schtasks /create /sc minute /mo  02 00 
		$a_80_3 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 } //vssadmin.exe Delete Shadows /All /Quiet  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Filecoder_ARA_MTB_7{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {6c 6f 63 6b 65 64 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //02 00  locked@onionmail.org
		$a_01_1 = {6c 69 76 65 74 65 61 6d 40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //02 00  liveteam@onionmail.org
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //02 00  Your file has been encrypted
		$a_01_3 = {45 6e 63 72 79 70 74 48 69 64 64 65 6e 46 69 6c 65 73 } //02 00  EncryptHiddenFiles
		$a_01_4 = {45 6e 63 72 79 70 74 48 69 64 64 65 6e 44 69 72 65 63 74 6f 72 69 65 73 } //00 00  EncryptHiddenDirectories
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Filecoder_ARA_MTB_8{
	meta:
		description = "Trojan:Win32/Filecoder.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 62 72 65 61 63 68 65 64 20 61 6e 64 20 61 6c 6c 20 64 61 74 61 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 2e 20 50 6c 65 61 73 65 20 63 6f 6e 74 61 63 74 20 75 73 20 61 74 3a } //02 00  Your network has been breached and all data was encrypted. Please contact us at:
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 61 61 7a 73 62 73 67 79 61 35 36 35 76 6c 75 32 63 36 62 7a 79 36 79 66 69 65 62 6b 63 62 74 76 76 63 79 74 76 6f 6c 74 33 33 73 37 37 78 79 70 69 37 6e 79 70 78 79 64 2e 6f 6e 69 6f 6e 2f } //00 00  https://aazsbsgya565vlu2c6bzy6yfiebkcbtvvcytvolt33s77xypi7nypxyd.onion/
	condition:
		any of ($a_*)
 
}