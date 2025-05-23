
rule Trojan_Win32_Stealer_AK_MTB{
	meta:
		description = "Trojan:Win32/Stealer.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 6d 5f 53 63 72 6f 6c 6c 42 6f 74 74 6f 6d 54 69 6d 65 72 } //1 tm_ScrollBottomTimer
		$a_01_1 = {63 6b 5f 43 75 72 73 6f 72 52 65 63 6f 72 64 43 6c 69 63 6b } //1 ck_CursorRecordClick
		$a_01_2 = {41 70 70 65 61 72 61 6e 63 65 2e 42 61 63 6b 47 72 6f 75 6e 64 46 69 6c 6c 2e 47 6c 6f 77 } //1 Appearance.BackGroundFill.Glow
		$a_01_3 = {47 61 74 65 77 61 79 49 50 41 64 64 72 65 73 73 49 6e 66 6f 72 6d 61 74 69 6f 6e 43 6f 6c 6c 65 63 74 69 6f 6e } //1 GatewayIPAddressInformationCollection
		$a_01_4 = {53 00 41 00 46 00 6c 00 61 00 73 00 68 00 50 00 6c 00 61 00 79 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 SAFlashPlayer.exe
		$a_01_5 = {73 00 65 00 2e 00 6b 00 65 00 79 00 } //1 se.key
		$a_01_6 = {4f 00 62 00 73 00 69 00 64 00 69 00 75 00 6d 00 } //1 Obsidium
		$a_01_7 = {54 00 54 00 41 00 42 00 4b 00 45 00 59 00 53 00 45 00 54 00 } //1 TTABKEYSET
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_Win32_Stealer_AK_MTB_2{
	meta:
		description = "Trojan:Win32/Stealer.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 43 00 72 00 79 00 70 00 74 00 6f 00 67 00 72 00 61 00 70 00 68 00 79 00 2e 00 41 00 65 00 73 00 43 00 72 00 79 00 70 00 74 00 6f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 } //1 System.Security.Cryptography.AesCryptoServiceProvider
		$a_01_1 = {64 00 66 00 70 00 61 00 74 00 68 00 } //1 dfpath
		$a_01_2 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 30 00 7d 00 } //1 {11111-22222-50001-00000}
		$a_01_3 = {47 00 65 00 74 00 44 00 65 00 6c 00 65 00 67 00 61 00 74 00 65 00 46 00 6f 00 72 00 46 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 50 00 6f 00 69 00 6e 00 74 00 65 00 72 00 } //1 GetDelegateForFunctionPointer
		$a_01_4 = {6c 00 69 00 63 00 65 00 6e 00 73 00 65 00 2e 00 6b 00 65 00 79 00 } //1 license.key
		$a_01_5 = {53 00 43 00 52 00 49 00 50 00 54 00 } //1 SCRIPT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}