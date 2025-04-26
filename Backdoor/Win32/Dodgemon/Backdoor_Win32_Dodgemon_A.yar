
rule Backdoor_Win32_Dodgemon_A{
	meta:
		description = "Backdoor:Win32/Dodgemon.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 73 79 73 62 6f 6f 74 2e 73 63 72 } //2 shell\open\Command=sysboot.scr
		$a_01_1 = {25 73 6d 6f 76 65 20 2f 59 20 22 25 73 22 20 22 25 73 22 } //2 %smove /Y "%s" "%s"
		$a_01_2 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 70 6f 72 74 6f 70 65 6e 69 6e 67 20 55 44 50 20 25 64 } //2 netsh firewall add portopening UDP %d
		$a_01_3 = {26 68 6f 73 74 6e 61 6d 65 3d 25 73 26 6d 79 69 70 3d 25 73 } //2 &hostname=%s&myip=%s
		$a_01_4 = {2b 4f 4b 20 25 64 20 25 25 64 } //1 +OK %d %%d
		$a_01_5 = {2f 70 6c 61 69 6e 3b 20 63 68 61 72 73 65 74 3d 67 62 6b } //1 /plain; charset=gbk
		$a_01_6 = {3b 20 66 69 6c 65 6e 61 6d 65 3d 22 61 74 74 61 63 68 6d 65 6e 74 31 22 } //1 ; filename="attachment1"
		$a_01_7 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e 20 42 4f 44 59 3d 38 42 49 54 4d 49 4d 45 } //1 MAIL FROM:<%s> BODY=8BITMIME
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=10
 
}