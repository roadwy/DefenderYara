
rule Ransom_Win32_BabukAgent_PA_MTB{
	meta:
		description = "Ransom:Win32/BabukAgent.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 20 73 75 63 6b } //1 You suck
		$a_01_1 = {48 61 20 48 61 20 48 41 20 21 } //1 Ha Ha HA !
		$a_01_2 = {41 00 64 00 77 00 54 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 AdwTest.exe
		$a_01_3 = {5c 73 74 6f 70 2d 61 64 77 2e 74 78 74 } //1 \stop-adw.txt
		$a_01_4 = {6d 20 61 20 62 61 64 20 6d 6f 74 68 65 72 20 66 75 63 6b 65 72 20 21 } //1 m a bad mother fucker !
		$a_01_5 = {59 6f 75 20 72 65 61 6c 79 20 74 68 69 6e 6b 20 79 6f 75 20 63 61 6e 20 65 73 63 61 70 65 20 6d 65 } //1 You realy think you can escape me
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}