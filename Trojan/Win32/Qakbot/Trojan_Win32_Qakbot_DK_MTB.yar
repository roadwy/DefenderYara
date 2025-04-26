
rule Trojan_Win32_Qakbot_DK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 80 0d 00 00 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 6a 00 e8 ?? ?? ?? ?? 8b d8 a1 ?? ?? ?? ?? 83 c0 04 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_DK_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6f 75 74 2e 64 6c 6c } //1 out.dll
		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
		$a_81_3 = {61 6e 6f 6d 6f 65 61 6e 69 73 6d } //1 anomoeanism
		$a_81_4 = {63 68 6f 72 65 6f 67 72 61 70 68 69 63 61 6c } //1 choreographical
		$a_81_5 = {61 70 6f 64 69 63 74 69 63 61 6c 6c 79 } //1 apodictically
		$a_81_6 = {67 61 6c 76 61 6e 6f 74 68 65 72 6d 6f 6d 65 74 65 72 } //1 galvanothermometer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win32_Qakbot_DK_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {6b 49 4f 5f 6e 65 77 5f 73 73 6c 5f 63 6f 6e 6e 65 63 74 } //1 kIO_new_ssl_connect
		$a_01_1 = {6b 49 4f 5f 6e 65 77 5f 62 75 66 66 65 72 5f 73 73 6c 5f 63 6f 6e 6e 65 63 74 } //1 kIO_new_buffer_ssl_connect
		$a_01_2 = {6b 49 4f 5f 73 73 6c 5f 73 68 75 74 64 6f 77 6e } //1 kIO_ssl_shutdown
		$a_01_3 = {6b 45 4d 5f 72 65 61 64 5f 62 69 6f 5f 53 53 4c 5f 53 45 53 53 49 4f 4e } //1 kEM_read_bio_SSL_SESSION
		$a_01_4 = {6b 53 4c 5f 43 4f 4d 50 5f 61 64 64 5f 63 6f 6d 70 72 65 73 73 69 6f 6e 5f 6d 65 74 68 6f 64 } //1 kSL_COMP_add_compression_method
		$a_01_5 = {6b 53 4c 5f 43 54 58 5f 63 68 65 63 6b 5f 70 72 69 76 61 74 65 5f 6b 65 79 } //1 kSL_CTX_check_private_key
		$a_01_6 = {6b 53 4c 5f 43 54 58 5f 67 65 74 5f 71 75 69 65 74 5f 73 68 75 74 64 6f 77 6e } //1 kSL_CTX_get_quiet_shutdown
		$a_01_7 = {6b 53 4c 5f 43 4f 4e 46 5f 43 54 58 5f 73 65 74 31 5f 70 72 65 66 69 78 } //1 kSL_CONF_CTX_set1_prefix
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}