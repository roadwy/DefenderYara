
rule Trojan_Win32_Tougle_A_bit{
	meta:
		description = "Trojan:Win32/Tougle.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {00 2f 63 68 6b 00 } //1 ⼀档k
		$a_01_1 = {2f 73 63 20 4f 4e 4c 4f 47 4f 4e 20 2f 64 65 6c 61 79 20 30 30 30 30 3a 30 35 20 2f } //1 /sc ONLOGON /delay 0000:05 /
		$a_01_2 = {61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76 77 78 79 7a 61 61 61 65 65 65 6f 6f 6f 75 75 75 69 69 69 79 79 79 } //1 abcdefghijklmnopqrstuvwxyzaaaeeeooouuuiiiyyy
		$a_01_3 = {63 6d 64 20 2f 63 20 22 22 25 73 25 73 25 73 25 73 2e 65 78 65 } //1 cmd /c ""%s%s%s%s.exe
		$a_01_4 = {00 62 69 74 73 61 64 6d 69 6e 2e 65 78 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}