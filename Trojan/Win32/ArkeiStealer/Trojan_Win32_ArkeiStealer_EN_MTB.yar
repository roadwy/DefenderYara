
rule Trojan_Win32_ArkeiStealer_EN_MTB{
	meta:
		description = "Trojan:Win32/ArkeiStealer.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {62 6b 6a 79 76 77 78 74 6c 6a 77 68 65 6b 62 6a 75 72 74 6a 6c 6e 75 6a 72 74 69 6a 79 78 6e 77 69 75 65 62 68 72 76 65 71 77 7a 65 71 72 76 65 } //1 bkjyvwxtljwhekbjurtjlnujrtijyxnwiuebhrveqwzeqrve
		$a_01_1 = {43 6f 75 6c 64 20 6e 6f 74 20 67 65 74 20 61 20 68 61 6e 64 6c 65 20 74 6f 20 6e 74 64 6c 6c 2e 64 6c 6c } //1 Could not get a handle to ntdll.dll
		$a_01_2 = {4e 74 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e } //1 NtUnmapViewOfSection
		$a_01_3 = {70 75 6b 6c 44 45 56 41 50 39 44 53 66 76 46 57 4a 53 57 69 70 54 53 49 52 53 44 6e 38 48 66 78 6c 73 45 5a 64 71 43 55 33 71 56 4a 46 63 31 33 } //1 puklDEVAP9DSfvFWJSWipTSIRSDn8HfxlsEZdqCU3qVJFc13
		$a_01_4 = {41 70 70 50 6f 6c 69 63 79 47 65 74 50 72 6f 63 65 73 73 54 65 72 6d 69 6e 61 74 69 6f 6e 4d 65 74 68 6f 64 } //1 AppPolicyGetProcessTerminationMethod
		$a_01_5 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //1 GetStartupInfoW
		$a_01_6 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}