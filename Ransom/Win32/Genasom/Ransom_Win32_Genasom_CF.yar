
rule Ransom_Win32_Genasom_CF{
	meta:
		description = "Ransom:Win32/Genasom.CF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_03_0 = {ac 0f be c0 50 0f be 4e 02 01 c8 ab 58 50 0f be 0e 01 c8 ab 92 58 83 c0 40 ab 92 83 c0 40 ab 59 8b 81 ?? 00 00 00 } //4
		$a_00_1 = {38 39 30 33 30 30 30 30 30 30 30 } //2 89030000000
		$a_00_2 = {6d 79 6e 75 6d } //2 mynum
		$a_00_3 = {6d 79 6e 65 77 69 70 } //2 mynewip
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //1 SOFTWARE\Microsoft\Internet Explorer
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e } //1 Software\Microsoft\Windows NT\CurrentVersion\Winlogon
		$a_00_6 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 53 61 66 65 42 6f 6f 74 } //1 System\CurrentControlSet\Control\SafeBoot
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=10
 
}