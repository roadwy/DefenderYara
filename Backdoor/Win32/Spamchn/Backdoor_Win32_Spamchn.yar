
rule Backdoor_Win32_Spamchn{
	meta:
		description = "Backdoor:Win32/Spamchn,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {2c 53 75 62 48 6f 73 74 3a } //1 ,SubHost:
		$a_01_2 = {4c 6f 67 69 6e 73 3b } //1 Logins;
		$a_01_3 = {5c 53 79 6e 53 65 6e 64 2e 65 78 65 } //1 \SynSend.exe
		$a_01_4 = {32 31 38 2e 37 2e 31 32 30 2e 37 30 } //1 218.7.120.70
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}