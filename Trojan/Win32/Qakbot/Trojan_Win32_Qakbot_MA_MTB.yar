
rule Trojan_Win32_Qakbot_MA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 4c 55 61 37 } //3 ALUa7
		$a_01_1 = {50 48 59 53 54 32 4a 58 33 } //3 PHYST2JX3
		$a_01_2 = {55 59 68 34 31 75 62 } //3 UYh41ub
		$a_01_3 = {56 65 6d 66 61 34 57 4e } //3 Vemfa4WN
		$a_01_4 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //1 DrawThemeIcon
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1) >=13
 
}
rule Trojan_Win32_Qakbot_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {64 69 76 5a 2e 64 6c 6c } //1 divZ.dll
		$a_01_2 = {41 68 42 46 6a 61 65 44 43 6d } //1 AhBFjaeDCm
		$a_01_3 = {43 33 74 42 41 71 34 61 74 61 6c } //1 C3tBAq4atal
		$a_01_4 = {4a 45 52 79 53 70 70 6b 50 } //1 JERySppkP
		$a_01_5 = {4a 65 74 47 37 54 65 4b 6d 31 74 } //1 JetG7TeKm1t
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win32_Qakbot_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 65 74 56 65 72 73 69 6f 6e 49 6e 66 6f } //2 PetVersionInfo
		$a_01_1 = {50 61 76 61 5f 63 6f 6d 5f 73 75 6e 5f 73 74 61 72 5f 73 64 62 63 78 5f 63 6f 6d 70 5f 68 73 71 6c 64 62 5f 53 74 6f 72 61 67 65 4e 61 74 69 76 65 4f 75 74 70 75 74 53 74 72 65 61 6d 5f 77 72 69 74 65 } //2 Pava_com_sun_star_sdbcx_comp_hsqldb_StorageNativeOutputStream_write
		$a_01_2 = {50 6f 6d 70 6f 6e 65 6e 74 5f 67 65 74 46 61 63 74 6f 72 79 } //2 Pomponent_getFactory
		$a_01_3 = {50 61 76 61 5f 63 6f 6d 5f 73 75 6e 5f 73 74 61 72 5f 73 64 62 63 78 5f 63 6f 6d 70 5f 68 73 71 6c 64 62 5f 4e 61 74 69 76 65 53 74 6f 72 61 67 65 41 63 63 65 73 73 } //2 Pava_com_sun_star_sdbcx_comp_hsqldb_NativeStorageAccess
		$a_01_4 = {50 61 76 61 5f 63 6f 6d 5f 73 75 6e 5f 73 74 61 72 5f 73 64 62 63 78 5f 63 6f 6d 70 5f 68 73 71 6c 64 62 5f 53 74 6f 72 61 67 65 4e 61 74 69 76 65 4f 75 74 70 75 74 53 74 72 65 61 6d 5f 77 72 69 74 65 5f 5f 4c 6a 61 76 61 5f 6c 61 6e 67 5f 53 74 72 69 6e 67 5f 32 4c 6a 61 76 61 5f 6c 61 6e 67 5f 53 74 72 69 6e 67 } //2 Pava_com_sun_star_sdbcx_comp_hsqldb_StorageNativeOutputStream_write__Ljava_lang_String_2Ljava_lang_String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}