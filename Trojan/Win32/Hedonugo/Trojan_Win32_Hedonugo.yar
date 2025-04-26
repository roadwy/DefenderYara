
rule Trojan_Win32_Hedonugo{
	meta:
		description = "Trojan:Win32/Hedonugo,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_01_0 = {4d 8b d0 48 8b c1 49 8b 0a 49 8b 52 08 4d 8b 42 10 4d 8b 4a 18 4c 8b d1 0f 05 } //1
		$a_00_1 = {63 72 65 61 74 65 20 61 66 64 5f 64 65 76 69 63 65 5f 68 61 6e 64 6c 65 20 66 61 69 6c 65 64 } //1 create afd_device_handle failed
		$a_01_2 = {73 7a 4b 61 73 70 65 72 73 6b 79 46 69 6c 65 } //1 szKasperskyFile
		$a_01_3 = {61 66 64 44 65 76 69 63 65 4e 61 6d 65 } //1 afdDeviceName
		$a_00_4 = {69 6d 70 65 72 73 6f 6e 61 74 69 6f 6e 5f 68 61 6e 64 6c 65 } //1 impersonation_handle
		$a_00_5 = {70 69 70 65 5f 68 61 6e 64 6c 65 5f 66 6f 72 5f 73 70 72 61 79 } //1 pipe_handle_for_spray
		$a_00_6 = {43 72 65 61 74 65 53 6f 63 6b 65 74 20 69 73 20 66 61 69 6c 65 64 } //1 CreateSocket is failed
		$a_02_7 = {5c 45 78 70 6c 6f 69 74 4b 69 74 5c [0-ff] 2e 70 64 62 } //1
		$a_00_8 = {4c 50 45 5f 41 46 44 } //1 LPE_AFD
		$a_00_9 = {44 65 73 74 72 6f 79 45 6e 76 } //1 DestroyEnv
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=5
 
}