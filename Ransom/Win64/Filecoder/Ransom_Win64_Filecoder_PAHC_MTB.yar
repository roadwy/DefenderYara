
rule Ransom_Win64_Filecoder_PAHC_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.PAHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin delete shadows /all /quiet
		$a_01_1 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //1 wbadmin delete catalog -quiet
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //2 YOUR FILES ARE ENCRYPTED
		$a_01_3 = {63 6d 64 20 2f 63 20 72 65 67 20 61 64 64 20 48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 6d 73 2d 73 65 74 74 69 6e 67 73 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 20 2f 76 20 44 65 6c 65 67 61 74 65 45 78 65 63 75 74 65 20 2f 66 } //1 cmd /c reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /f
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=6
 
}