
rule Ransom_Win32_Filecoder_PAGQ_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.PAGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 22 76 73 73 61 64 6d 69 6e 20 44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 22 } //2 cmd /c "vssadmin Delete Shadows /All /Quiet"
		$a_01_1 = {63 6d 64 20 2f 63 20 22 62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 69 67 6e 6f 72 65 61 6c 6c 66 61 69 6c 75 72 65 73 22 } //2 cmd /c "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
		$a_01_2 = {63 6d 64 20 2f 63 20 22 74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d } //1 cmd /c "taskkill /F /IM
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}