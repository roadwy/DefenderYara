
rule Trojan_Win32_Cogebot_A{
	meta:
		description = "Trojan:Win32/Cogebot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 04 33 ff 75 90 01 01 34 90 01 01 ff 45 90 01 01 88 06 46 ff d7 90 00 } //2
		$a_01_1 = {25 61 70 70 64 61 74 61 25 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 %appdata%\svchost.exe
		$a_01_2 = {57 69 6e 64 6f 77 73 20 53 65 72 76 69 63 65 20 48 6f 73 74 } //1 Windows Service Host
		$a_01_3 = {21 64 6f 77 6e 6c 6f 61 64 } //1 !download
		$a_01_4 = {21 75 70 64 61 74 65 } //1 !update
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}