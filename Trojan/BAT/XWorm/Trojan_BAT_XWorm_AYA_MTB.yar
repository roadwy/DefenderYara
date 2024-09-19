
rule Trojan_BAT_XWorm_AYA_MTB{
	meta:
		description = "Trojan:BAT/XWorm.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 42 6f 74 4b 69 6c 6c 65 72 } //2 RunBotKiller
		$a_01_1 = {44 65 74 65 63 74 56 69 72 74 75 61 6c 4d 61 63 68 69 6e 65 } //2 DetectVirtualMachine
		$a_01_2 = {44 65 74 65 63 74 44 65 62 75 67 67 65 72 } //2 DetectDebugger
		$a_01_3 = {44 65 74 65 63 74 53 61 6e 64 62 6f 78 69 65 } //2 DetectSandboxie
		$a_01_4 = {43 72 65 61 74 65 4d 75 74 65 78 } //1 CreateMutex
		$a_01_5 = {70 61 79 6c 6f 61 64 } //1 payload
		$a_00_6 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 Select * from Win32_ComputerSystem
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=11
 
}