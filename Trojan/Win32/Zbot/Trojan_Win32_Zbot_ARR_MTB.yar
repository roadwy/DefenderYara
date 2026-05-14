
rule Trojan_Win32_Zbot_ARR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_81_0 = {63 6f 70 79 20 2f 79 20 22 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 6c 6f 6f 70 2e 65 78 65 22 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4e 54 22 3e 20 6e 75 6c } //20 copy /y "C:\Windows\system\loop.exe" "C:\Program Files\Windows NT"> nul
		$a_81_1 = {53 43 48 54 41 53 4b 53 20 2f 43 72 65 61 74 65 20 2f 54 4e 20 25 6e 61 6d 65 25 20 2f 54 52 20 22 27 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 5c 5a 6c 6f 6f 70 2e 65 78 65 } //5 SCHTASKS /Create /TN %name% /TR "'C:\Windows\system\Zloop.exe
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*5) >=25
 
}