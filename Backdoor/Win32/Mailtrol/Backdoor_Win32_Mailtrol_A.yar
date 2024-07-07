
rule Backdoor_Win32_Mailtrol_A{
	meta:
		description = "Backdoor:Win32/Mailtrol.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 69 74 68 75 62 2e 63 6f 6d 2f 54 68 6f 6d 73 6f 6e 52 65 75 74 65 72 73 45 69 6b 6f 6e 2f 67 6f 2d 6e 74 6c 6d } //1 github.com/ThomsonReutersEikon/go-ntlm
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 73 74 61 61 6c 64 72 61 61 64 2f 67 6f 2d 6e 74 6c 6d } //1 github.com/staaldraad/go-ntlm
		$a_01_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 75 72 66 61 76 65 2f 63 6c 69 } //1 github.com/urfave/cli
		$a_01_3 = {73 65 6e 73 65 70 6f 73 74 2f 72 75 6c 65 72 2f } //1 sensepost/ruler/
		$a_01_4 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 63 61 6c 63 2e 65 78 65 } //1 C:\Windows\System32\calc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}