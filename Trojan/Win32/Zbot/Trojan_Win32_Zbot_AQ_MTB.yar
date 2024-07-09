
rule Trojan_Win32_Zbot_AQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 db 8a da 80 f3 08 80 38 00 74 06 38 18 74 02 30 18 40 42 3b 15 [0-04] 76 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Zbot_AQ_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 75 08 bb 0a 00 00 00 8b 4d 0c c1 e9 02 33 d2 8b 45 0c c1 e8 02 2b c1 50 f7 f3 83 c2 02 29 16 33 d2 58 f7 f3 03 14 24 81 c2 a0 82 f9 45 31 16 83 c6 04 e2 d9 } //1
		$a_80_1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 59 39 44 66 50 73 77 52 72 2e 65 78 65 } //C:\Documents and Settings\All Users\Start Menu\Programs\Startup\Y9DfPswRr.exe  1
	condition:
		((#a_00_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}