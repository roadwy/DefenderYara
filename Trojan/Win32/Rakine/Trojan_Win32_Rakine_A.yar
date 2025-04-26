
rule Trojan_Win32_Rakine_A{
	meta:
		description = "Trojan:Win32/Rakine.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 } //1 SOFTWARE\Borland\Delphi
		$a_01_1 = {6b 61 72 69 6e 65 2e 63 6f 2e 6b 72 2f 64 6f 77 6e 6c 6f 61 64 2f 77 69 6e 75 70 64 61 74 65 2e 73 79 73 } //1 karine.co.kr/download/winupdate.sys
		$a_01_2 = {55 70 64 61 74 65 5f 4b 69 6c } //1 Update_Kil
		$a_01_3 = {74 61 6b 65 69 74 2e 65 78 65 } //1 takeit.exe
		$a_01_4 = {74 61 6b 65 69 74 2e 73 79 73 } //1 takeit.sys
		$a_01_5 = {32 32 30 2e 39 35 2e 32 33 31 2e 31 39 37 2f 69 6e 73 74 61 6c 6c 5f 63 6f 75 6e 74 } //1 220.95.231.197/install_count
		$a_01_6 = {77 69 6e 75 70 64 61 74 65 2e 65 78 65 } //1 winupdate.exe
		$a_01_7 = {32 32 30 2e 39 35 2e 32 33 31 2e 31 39 37 2f 61 63 63 65 73 73 5f 63 6f 75 6e 74 } //1 220.95.231.197/access_count
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}