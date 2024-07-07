
rule Worm_Win32_Bobax_gen_B{
	meta:
		description = "Worm:Win32/Bobax.gen!B,SIGNATURE_TYPE_PEHSTR,11 00 10 00 11 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6c 69 6e 2d 30 25 64 2e 6d } //2 mailin-0%d.m
		$a_01_1 = {52 43 50 54 20 54 4f 3a 20 3c } //2 RCPT TO: <
		$a_01_2 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c } //2 MAIL FROM: <
		$a_01_3 = {57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Windows\CurrentVersion\Run
		$a_01_4 = {2d 3d 5f 4e 65 78 74 50 61 72 74 5f 25 30 33 64 } //2 -=_NextPart_%03d
		$a_01_5 = {52 4e 44 5f 44 49 47 49 54 } //2 RND_DIGIT
		$a_01_6 = {52 4e 44 5f 46 52 4f 4d 5f 44 4f 4d 41 49 4e } //2 RND_FROM_DOMAIN
		$a_01_7 = {73 6d 74 70 72 65 6c 61 79 } //2 smtprelay
		$a_01_8 = {74 6f 65 6d 61 69 6c } //2 toemail
		$a_01_9 = {66 72 6f 6d 65 6d 61 69 6c } //2 fromemail
		$a_01_10 = {6c 6f 63 61 6c 68 6f 73 74 2f 65 78 65 2e 65 78 65 } //1 localhost/exe.exe
		$a_01_11 = {46 69 72 65 77 61 6c 6c 4f 76 65 72 72 69 64 65 } //1 FirewallOverride
		$a_01_12 = {46 69 72 65 77 61 6c 6c 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 FirewallDisableNotify
		$a_01_13 = {41 6e 74 69 56 69 72 75 73 4f 76 65 72 72 69 64 65 } //1 AntiVirusOverride
		$a_01_14 = {41 6e 74 69 56 69 72 75 73 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 } //1 AntiVirusDisableNotify
		$a_01_15 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //1 SOFTWARE\Microsoft\Security Center
		$a_01_16 = {66 69 72 65 77 61 6c 6c 20 73 65 74 } //1 firewall set
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1) >=16
 
}