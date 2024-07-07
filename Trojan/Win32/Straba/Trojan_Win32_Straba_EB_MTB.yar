
rule Trojan_Win32_Straba_EB_MTB{
	meta:
		description = "Trojan:Win32/Straba.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 47 42 48 4e 4a 4d 4b 2e 44 4c 4c } //1 FGBHNJMK.DLL
		$a_01_1 = {46 66 67 62 48 67 79 62 68 } //1 FfgbHgybh
		$a_01_2 = {46 67 62 79 68 6e 4b 6a 67 76 } //1 FgbyhnKjgv
		$a_01_3 = {54 74 66 76 79 67 62 4b 68 62 67 66 } //1 TtfvygbKhbgf
		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 49 64 } //1 GetCurrentThreadId
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Straba_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Straba.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 6c 66 2e 65 78 65 } //1 Self.exe
		$a_01_1 = {4d 56 59 73 66 69 72 73 74 63 72 65 65 70 65 74 68 } //1 MVYsfirstcreepeth
		$a_01_2 = {59 6f 75 2e 6c 6c 6e 66 61 63 65 76 45 72 64 72 79 6a 77 68 61 6c 65 73 74 68 65 69 72 } //1 You.llnfacevErdryjwhalestheir
		$a_01_3 = {49 33 7a 45 6c 69 66 65 68 65 61 76 65 6e 77 } //1 I3zElifeheavenw
		$a_01_4 = {73 65 61 49 30 51 69 73 } //1 seaI0Qis
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}