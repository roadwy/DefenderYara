
rule Trojan_Win32_Wepiall_A{
	meta:
		description = "Trojan:Win32/Wepiall.A,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_03_0 = {56 67 63 51 7d 71 71 66 69 ?? ?? ?? 23 4a 6b 6f 69 22 45 6e 69 28 56 64 70 75 6b 66 66 2a } //10
		$a_03_1 = {4a 6b 69 6f 44 64 6e ?? ?? ?? 21 75 61 61 21 52 6c 73 74 6d 60 64 } //10
		$a_01_2 = {71 60 6d 74 67 6c 79 6c 7b 2c 63 30 36 3a 30 2a 6a 7a 66 } //1 q`mtglyl{,c06:0*jzf
		$a_01_3 = {6d 23 43 6d 6e 26 51 66 71 74 68 62 61 26 } //1 m#Cmn&Qfqthba&
		$a_01_4 = {77 69 6e 25 63 61 25 63 62 25 63 64 2e 65 78 65 } //1 win%ca%cb%cd.exe
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}