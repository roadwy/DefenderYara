
rule Ransom_Win32_LockScreen_LK_MTB{
	meta:
		description = "Ransom:Win32/LockScreen.LK!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 6c 6c 79 64 62 67 2e 65 78 65 } //1 ollydbg.exe
		$a_01_1 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //1 ProcessHacker.exe
		$a_01_2 = {43 6f 6d 70 75 74 65 72 20 49 6e 66 6f 72 6d 61 74 69 6f 6e } //1 Computer Information
		$a_01_3 = {49 6e 66 6f 53 74 65 61 6c } //1 InfoSteal
		$a_01_4 = {69 73 52 61 6e 73 6f 6d 65 50 6f 70 75 70 } //1 isRansomePopup
		$a_01_5 = {72 61 6e 73 6f 6d 65 45 6e 63 50 61 74 68 } //1 ransomeEncPath
		$a_01_6 = {3a 38 30 38 33 2f 77 65 6c 63 6f 6d 65 2e 64 6f } //1 :8083/welcome.do
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}