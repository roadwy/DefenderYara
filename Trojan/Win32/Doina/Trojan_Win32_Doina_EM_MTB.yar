
rule Trojan_Win32_Doina_EM_MTB{
	meta:
		description = "Trojan:Win32/Doina.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 76 6f 68 6f 73 74 2e 62 61 74 } //1 svohost.bat
		$a_81_1 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 61 72 74 20 72 61 73 61 75 74 6f } //1 cmd /c net start rasauto
		$a_81_2 = {73 76 65 68 6f 73 74 2e 65 78 65 } //1 svehost.exe
		$a_81_3 = {6c 69 6e 6b 65 72 2e 62 69 6e } //1 linker.bin
		$a_81_4 = {63 6d 64 20 2f 63 20 78 63 6f 70 79 20 2f 73 20 2f 69 20 2f 68 20 2f 65 20 2f 71 20 2f 79 20 2f 64 } //1 cmd /c xcopy /s /i /h /e /q /y /d
		$a_81_5 = {63 6d 64 20 2f 63 20 69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c } //1 cmd /c ipconfig /all
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}