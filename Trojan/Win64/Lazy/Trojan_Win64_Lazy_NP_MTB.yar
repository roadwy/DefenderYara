
rule Trojan_Win64_Lazy_NP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_81_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 7b 7d } //2 cmd.exe /c {}
		$a_81_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c } //1 C:\Windows\System32\
		$a_81_2 = {58 5c 64 7b 36 7d 5c 2e 64 61 74 24 } //1 X\d{6}\.dat$
		$a_81_3 = {7b 7d 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 62 61 63 6b 75 70 5f 66 36 34 2e 65 78 65 } //1 {}Windows\System32\backup_f64.exe
		$a_81_4 = {73 74 61 72 74 20 22 22 20 22 7b 7d 22 } //1 start "" "{}"
		$a_81_5 = {7b 7d 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 7a 65 72 6f 5f 6c 6f 67 } //1 {}Windows\System32\czero_log
		$a_81_6 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 7b 7d 22 20 2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 74 72 20 22 7b 7d 22 20 2f 72 6c 20 48 49 47 48 45 53 54 20 2f 66 } //1 schtasks /create /tn "{}" /sc ONLOGON /tr "{}" /rl HIGHEST /f
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}