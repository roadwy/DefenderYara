
rule Backdoor_Win32_Misbot_A{
	meta:
		description = "Backdoor:Win32/Misbot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 89 d6 e8 ?? ?? ?? ?? ba 0a 00 00 00 89 d1 99 f7 f9 89 d3 c7 04 24 96 00 00 00 e8 } //2
		$a_00_1 = {43 3a 5c 55 73 65 72 73 5c 25 73 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 41 25 6c 69 2e 65 78 65 } //1 C:\Users\%s\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\A%li.exe
		$a_00_2 = {25 73 5c 42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } //1 %s\Bitcoin\wallet.dat
		$a_01_3 = {44 44 6f 53 20 74 68 72 65 61 64 20 74 65 72 6d 69 6e 61 74 69 6e 67 21 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}