
rule Trojan_Win32_CryptInject_TR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.TR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 57 49 4e 44 45 53 54 52 4f 59 45 52 2e 45 58 45 } //1 %s\WINDESTROYER.EXE
		$a_01_1 = {54 68 69 73 20 74 72 6f 6a 61 6e 20 69 73 20 6e 6f 74 20 61 20 6a 6f 6b 65 2c 20 63 6f 6e 74 69 6e 75 65 3f } //1 This trojan is not a joke, continue?
		$a_01_2 = {59 4f 55 52 20 53 59 53 54 45 4d 20 48 41 53 20 42 45 45 4e 20 44 45 53 54 52 4f 59 45 44 20 42 59 20 57 49 4e 44 45 53 54 52 4f 59 45 52 2e 45 58 45 } //1 YOUR SYSTEM HAS BEEN DESTROYED BY WINDESTROYER.EXE
		$a_01_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_01_4 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_01_5 = {44 69 73 61 62 6c 65 43 4d 44 } //1 DisableCMD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}