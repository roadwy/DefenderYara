
rule Trojan_Win32_SusPyExec_IK_MTB{
	meta:
		description = "Trojan:Win32/SusPyExec.IK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 5a 00 68 00 75 00 6a 00 69 00 6b 00 64 00 6f 00 } //1 C:\ProgramData\Zhujikdo
		$a_00_1 = {4c 00 69 00 62 00 5c 00 49 00 6d 00 61 00 67 00 65 00 2e 00 70 00 6e 00 67 00 } //1 Lib\Image.png
		$a_00_2 = {70 00 79 00 74 00 68 00 6f 00 6e 00 77 00 2e 00 65 00 78 00 65 00 } //1 pythonw.exe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}