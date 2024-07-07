
rule Worm_Win32_Tophos_E{
	meta:
		description = "Worm:Win32/Tophos.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 72 75 2f 65 78 70 6c 6f 79 65 72 2e 65 78 65 } //1 .ru/exployer.exe
		$a_01_1 = {63 6d 64 20 2f 63 20 63 68 63 70 20 31 32 35 31 20 26 26 20 73 79 73 74 65 6d 69 6e 66 6f 20 3e } //1 cmd /c chcp 1251 && systeminfo >
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}