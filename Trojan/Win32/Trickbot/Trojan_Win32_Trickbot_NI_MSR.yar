
rule Trojan_Win32_Trickbot_NI_MSR{
	meta:
		description = "Trojan:Win32/Trickbot.NI!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {46 6f 72 63 65 52 65 6d 6f 76 65 20 7b 39 41 45 43 32 38 37 39 2d 31 41 38 32 2d 34 46 45 41 2d 41 41 34 46 2d 36 30 42 39 38 44 33 41 43 32 39 33 7d 20 3d 20 73 20 27 53 61 6d 70 6c 65 20 53 70 65 6c 6c 20 43 68 65 63 6b 69 6e 67 20 50 72 6f 76 69 64 65 72 27 } //1 ForceRemove {9AEC2879-1A82-4FEA-AA4F-60B98D3AC293} = s 'Sample Spell Checking Provider'
		$a_81_1 = {53 61 6d 70 6c 65 53 70 65 6c 6c 69 6e 67 50 72 6f 76 69 64 65 72 2e 64 6c 6c } //1 SampleSpellingProvider.dll
		$a_81_2 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
		$a_81_3 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //1 DllGetClassObject
		$a_81_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_81_5 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllUnregisterServer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}