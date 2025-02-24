
rule Trojan_BAT_KillMBR_NK_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 09 17 58 9a 28 ?? 00 00 0a 13 08 02 11 08 28 06 00 00 06 } //3
		$a_01_1 = {24 33 66 38 35 66 66 30 66 2d 34 64 30 66 2d 34 65 61 62 2d 39 39 36 62 2d 62 64 66 61 65 64 66 61 35 33 36 33 } //1 $3f85ff0f-4d0f-4eab-996b-bdfaedfa5363
		$a_01_2 = {67 65 6f 6d 65 74 72 79 20 64 61 73 68 20 61 75 74 6f 20 62 6f 74 20 66 6f 72 20 65 78 74 72 65 6d 65 20 64 65 6d 6f 6e 73 } //1 geometry dash auto bot for extreme demons
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule Trojan_BAT_KillMBR_NK_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 00 42 00 52 00 20 00 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 } //2 MBR payload
		$a_01_1 = {6b 65 79 67 72 6f 75 70 37 37 37 } //2 keygroup777
		$a_01_2 = {24 66 30 30 37 31 36 31 35 2d 65 32 38 37 2d 34 36 65 66 2d 61 37 62 62 2d 33 39 34 63 35 38 33 65 32 38 62 39 } //1 $f0071615-e287-46ef-a7bb-394c583e28b9
		$a_01_3 = {4d 00 42 00 52 00 5f 00 4f 00 76 00 65 00 72 00 77 00 72 00 69 00 74 00 65 00 72 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 MBR_Overwriter.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}
rule Trojan_BAT_KillMBR_NK_MTB_3{
	meta:
		description = "Trojan:BAT/KillMBR.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 00 02 00 00 8d 11 00 00 01 0a 72 3d 00 00 70 20 00 00 00 10 19 7e 11 00 00 0a 19 16 7e 11 00 00 0a 28 13 00 00 06 0b } //3
		$a_01_1 = {47 44 49 5f 70 61 79 6c 6f 61 64 73 32 } //1 GDI_payloads2
		$a_01_2 = {2f 00 6b 00 20 00 72 00 65 00 67 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 48 00 4b 00 43 00 52 00 20 00 2f 00 66 00 } //1 /k reg delete HKCR /f
		$a_01_3 = {74 00 68 00 31 00 73 00 20 00 69 00 73 00 20 00 46 00 72 00 65 00 65 00 6d 00 61 00 73 00 6f 00 6e 00 72 00 79 00 } //1 th1s is Freemasonry
		$a_01_4 = {67 64 69 5f 6d 61 6c 77 61 72 65 } //1 gdi_malware
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}
rule Trojan_BAT_KillMBR_NK_MTB_4{
	meta:
		description = "Trojan:BAT/KillMBR.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {49 20 68 6f 70 65 20 79 6f 75 20 64 69 64 20 6e 6f 74 20 72 75 6e 20 74 68 69 73 20 6f 6e 20 61 20 72 65 61 6c 20 6d 61 63 68 69 6e 65 } //1 I hope you did not run this on a real machine
		$a_01_1 = {4e 6f 77 20 54 68 61 74 20 49 6d 20 54 68 69 6e 6b 69 6e 67 20 57 68 61 74 20 44 69 64 20 59 4f 55 20 54 48 49 49 4e 4b 20 54 4f 20 52 55 4e 20 54 48 49 53 20 4d 41 4c 57 41 52 45 3f } //1 Now That Im Thinking What Did YOU THIINK TO RUN THIS MALWARE?
		$a_01_2 = {41 6c 77 61 79 73 20 72 65 6d 65 6d 62 65 72 21 20 50 73 79 63 68 6f 6d 65 6d 65 20 69 73 20 68 65 72 65 21 } //1 Always remember! Psychomeme is here!
		$a_01_3 = {57 65 6c 63 6f 6d 65 20 54 6f 20 48 65 6c 6c } //1 Welcome To Hell
		$a_01_4 = {49 66 20 79 6f 75 20 6c 6f 6f 6b 20 61 74 20 74 68 69 73 20 73 63 72 65 65 6e 2c 20 79 6f 75 27 72 65 20 70 72 6f 62 61 62 6c 79 20 67 6f 6e 6e 61 20 68 61 76 65 20 61 20 62 61 64 20 74 69 6d 65 20 61 6e 64 20 64 72 65 61 6d 73 } //1 If you look at this screen, you're probably gonna have a bad time and dreams
		$a_01_5 = {42 74 77 2c 20 64 6f 20 6e 6f 74 20 74 72 79 20 66 69 78 69 6e 67 20 74 68 69 73 20 69 74 20 77 69 6c 6c 20 72 65 20 72 75 6e 20 61 67 61 69 6e 20 74 68 65 20 76 69 72 75 73 } //1 Btw, do not try fixing this it will re run again the virus
		$a_01_6 = {59 6f 75 72 20 53 79 73 74 65 6d 20 49 73 20 44 65 73 74 72 6f 79 65 64 } //1 Your System Is Destroyed
		$a_01_7 = {77 68 79 20 79 6f 75 20 72 75 6e 20 74 68 69 73 20 69 20 67 69 76 65 64 20 79 6f 75 20 32 20 77 61 72 6e 69 6e 67 27 73 20 61 6e 64 20 79 6f 75 72 20 70 63 20 67 6f 74 20 64 65 73 74 72 6f 79 65 64 20 69 6e 20 6c 65 73 73 20 74 68 61 6e 20 31 30 20 73 65 63 6f 6e 64 73 } //1 why you run this i gived you 2 warning's and your pc got destroyed in less than 10 seconds
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}