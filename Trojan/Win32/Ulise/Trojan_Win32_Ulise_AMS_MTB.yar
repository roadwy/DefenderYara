
rule Trojan_Win32_Ulise_AMS_MTB{
	meta:
		description = "Trojan:Win32/Ulise.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 65 72 4d 61 6e 61 67 65 72 } //1 MinerManager
		$a_01_1 = {4b 65 79 4c 6f 67 67 65 72 } //1 KeyLogger
		$a_01_2 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 43 52 45 41 54 45 20 2f 52 4c 20 48 49 47 48 45 53 54 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 54 52 } //1 schtasks.exe /CREATE /RL HIGHEST /SC ONLOGON /TR
		$a_01_3 = {6f 75 74 64 61 74 65 64 5f 63 6f 72 65 2e 65 78 65 } //1 outdated_core.exe
		$a_01_4 = {41 6e 61 6c 44 65 73 74 72 6f 79 65 72 2e 64 6c 6c } //1 AnalDestroyer.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}