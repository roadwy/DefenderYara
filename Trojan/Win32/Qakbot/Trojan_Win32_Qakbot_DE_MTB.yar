
rule Trojan_Win32_Qakbot_DE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 3b c2 ?? ?? 2a 5c 24 0c 8b 06 2b 4c 24 14 05 94 d4 08 01 03 cf 89 06 a3 ?? ?? ?? ?? 83 c6 04 8a c1 89 0d ?? ?? ?? ?? 2a 44 24 0c 04 6f 83 6c 24 10 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 61 64 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 41 } //3 LoadKeyboardLayoutA
		$a_81_1 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //3 OpenClipboard
		$a_81_2 = {6c 6b 74 67 57 65 63 72 58 79 54 7a 57 63 69 69 46 } //3 lktgWecrXyTzWciiF
		$a_81_3 = {69 74 77 69 65 63 76 71 65 72 } //3 itwiecvqer
		$a_81_4 = {70 56 5f 77 64 4a 43 53 68 4e 47 4f } //3 pV_wdJCShNGO
		$a_81_5 = {74 72 61 79 6e 6f 74 69 66 79 } //3 traynotify
		$a_81_6 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //3 ClientToScreen
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Qakbot_DE_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {6b 75 61 5f 70 75 73 68 6c 69 67 68 74 75 73 65 72 64 61 74 61 } //1 kua_pushlightuserdata
		$a_01_1 = {6b 75 61 5f 6e 65 77 75 73 65 72 64 61 74 61 } //1 kua_newuserdata
		$a_01_2 = {6b 75 61 5f 67 65 74 68 6f 6f 6b 6d 61 73 6b } //1 kua_gethookmask
		$a_01_3 = {6b 75 61 5f 70 75 73 68 76 66 73 74 72 69 6e 67 } //1 kua_pushvfstring
		$a_01_4 = {6d 75 73 74 } //1 must
		$a_01_5 = {6b 75 61 4c 5f 61 64 64 73 74 72 69 6e 67 } //1 kuaL_addstring
		$a_01_6 = {6b 75 61 4c 5f 62 75 66 66 69 6e 69 74 } //1 kuaL_buffinit
		$a_01_7 = {6b 75 61 4c 5f 67 65 74 6d 65 74 61 66 69 65 6c 64 } //1 kuaL_getmetafield
		$a_01_8 = {6b 75 61 4c 5f 70 72 65 70 62 75 66 66 65 72 } //1 kuaL_prepbuffer
		$a_01_9 = {6b 75 61 4c 5f 72 65 67 69 73 74 65 72 } //1 kuaL_register
		$a_01_10 = {6b 75 61 5f 63 68 65 63 6b 73 74 61 63 6b } //1 kua_checkstack
		$a_01_11 = {6b 6c 63 5f 65 6e 74 72 79 5f 63 6f 70 79 72 69 67 68 74 5f 5f 33 5f 30 5f 30 66 } //1 klc_entry_copyright__3_0_0f
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}