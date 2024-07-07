
rule Ransom_Win32_Genasom_AJ{
	meta:
		description = "Ransom:Win32/Genasom.AJ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 66 69 72 65 66 6f 78 2e 65 78 65 22 } //1
		$a_01_1 = {00 6f 70 65 72 61 2e 65 78 65 22 } //1
		$a_01_2 = {72 65 67 20 61 64 64 20 22 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 72 75 6e 22 20 } //1 reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\run" 
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 57 65 62 4d 6f 6e 65 79 5c 70 61 74 68 } //1 Software\WebMoney\path
		$a_01_4 = {73 00 6d 00 73 00 2d 00 70 00 72 00 69 00 63 00 65 00 2e 00 72 00 75 00 } //1 sms-price.ru
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}