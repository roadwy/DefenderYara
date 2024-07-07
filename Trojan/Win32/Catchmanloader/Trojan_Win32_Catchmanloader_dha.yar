
rule Trojan_Win32_Catchmanloader_dha{
	meta:
		description = "Trojan:Win32/Catchmanloader!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 57 69 6e 49 6e 73 74 61 6c 6c 2e 6c 6f 67 } //2 c:\windows\WinInstall.log
		$a_01_1 = {6d 42 33 4a 68 6c 72 6a 55 78 4c 31 59 4a 63 6e } //2 mB3JhlrjUxL1YJcn
		$a_01_2 = {69 6e 6a 65 63 74 2e 64 6c 6c 00 64 6c 6c 66 75 6e } //1
		$a_01_3 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 6a 65 63 74 20 74 68 65 20 44 4c 4c } //1 Failed to inject the DLL
		$a_01_4 = {52 65 66 6c 65 63 74 69 76 65 44 4c 4c 49 6e 6a 65 63 74 69 6f 6e 2d 6d 61 73 74 65 72 5c 52 65 6c 65 61 73 65 5c 69 6e 6a 65 63 74 2e 70 64 62 } //1 ReflectiveDLLInjection-master\Release\inject.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}