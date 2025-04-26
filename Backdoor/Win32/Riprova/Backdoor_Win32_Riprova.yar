
rule Backdoor_Win32_Riprova{
	meta:
		description = "Backdoor:Win32/Riprova,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 69 70 72 6f 76 61 2e 2e 2e 00 25 64 00 } //5
		$a_01_1 = {43 3a 5c 5c 73 67 72 75 6e 74 } //4 C:\\sgrunt
		$a_01_2 = {64 69 73 69 6e 73 74 61 6c 6c 61 2e 68 74 6d } //4 disinstalla.htm
		$a_01_3 = {49 45 34 33 32 31 2e 65 78 65 } //3 IE4321.exe
		$a_01_4 = {77 77 77 2e 73 67 72 75 6e 74 2e 62 69 7a 2f } //4 www.sgrunt.biz/
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*4) >=13
 
}
rule Backdoor_Win32_Riprova_2{
	meta:
		description = "Backdoor:Win32/Riprova,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 69 70 72 6f 76 61 2e 2e 2e 00 25 64 00 } //5
		$a_01_1 = {5c 76 65 72 73 69 6f 6e 5c 4e 76 73 76 53 79 73 2e 65 78 65 } //4 \version\NvsvSys.exe
		$a_01_2 = {52 45 53 4f 55 52 00 6f 70 65 6e 00 } //4 䕒体剕漀数n
		$a_01_3 = {54 6f 20 75 6e 69 6e 73 74 61 6c 6c 20 70 6c 65 61 73 65 20 73 65 6e 64 20 61 6e 20 65 6d 61 69 6c 20 61 74 20 74 68 69 73 20 61 64 64 72 65 73 73 3a 0a 0d 00 } //3
		$a_01_4 = {75 6e 69 6e 73 74 61 6c 6c 40 73 65 63 75 72 69 7a 65 2e 62 69 7a } //5 uninstall@securize.biz
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*5) >=11
 
}
rule Backdoor_Win32_Riprova_3{
	meta:
		description = "Backdoor:Win32/Riprova,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //2 SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\User Agent\Post Platform
		$a_01_1 = {64 69 61 6c 6e 6f 00 } //2
		$a_01_2 = {7c 64 69 61 6c 00 } //2 摼慩l
		$a_01_3 = {52 69 70 72 6f 76 61 2e 2e 2e 00 25 64 00 } //6
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 4d 61 70 5c 44 6f 6d 61 69 6e 73 5c } //1 Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\
		$a_01_5 = {53 67 72 75 6e 74 7c 56 } //2 Sgrunt|V
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 54 54 75 6e 69 6d } //4 SOFTWARE\Microsoft\Windows\CurrentVersion\TTunim
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*6+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*4) >=10
 
}
rule Backdoor_Win32_Riprova_4{
	meta:
		description = "Backdoor:Win32/Riprova,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 0f 00 00 "
		
	strings :
		$a_01_0 = {43 26 6c 6f 73 65 20 48 65 6c 70 20 61 6e 64 20 49 6e 74 65 72 6e 65 74 } //4 C&lose Help and Internet
		$a_01_1 = {2e 63 6f 6d 2f 69 6e 64 65 78 32 2e 70 68 70 } //4 .com/index2.php
		$a_01_2 = {61 72 63 68 69 76 69 6f 73 65 78 2e 63 6f 6d } //2 archiviosex.com
		$a_01_3 = {61 72 63 68 69 76 69 6f 68 61 72 64 2e 63 6f 6d } //2 archiviohard.com
		$a_01_4 = {50 61 73 73 77 6f 72 64 20 64 69 20 41 63 63 65 73 73 6f 20 43 6f 6e 74 65 6e 75 74 69 20 50 72 69 76 61 74 69 } //4 Password di Accesso Contenuti Privati
		$a_01_5 = {54 69 20 73 65 69 20 64 69 73 63 6f 6e 6e 65 73 73 6f 2c 20 76 75 6f 69 20 72 69 63 6f 6c 6c 65 67 61 72 74 69 20 3f } //4 Ti sei disconnesso, vuoi ricollegarti ?
		$a_01_6 = {63 3a 5c 70 61 73 73 } //3 c:\pass
		$a_01_7 = {52 69 70 72 6f 76 61 2e 2e 2e 00 25 64 00 } //5
		$a_01_8 = {69 73 64 6e 00 00 00 00 6d 6f 64 65 6d 00 00 } //3
		$a_01_9 = {52 61 73 48 61 6e 67 55 70 41 } //1 RasHangUpA
		$a_01_10 = {52 61 73 44 69 61 6c 41 } //1 RasDialA
		$a_01_11 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 53 74 61 74 75 73 41 } //1 RasGetConnectStatusA
		$a_01_12 = {64 69 61 6c 6e 6f 00 } //4
		$a_01_13 = {73 6e 70 72 74 7a 7c } //4 snprtz|
		$a_01_14 = {59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 64 69 73 63 6f 6e 6e 65 63 74 65 64 2c 20 64 6f 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 63 6f 6e 6e 65 63 74 3f } //3 You have been disconnected, do you want to reconnect?
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4+(#a_01_6  & 1)*3+(#a_01_7  & 1)*5+(#a_01_8  & 1)*3+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*4+(#a_01_13  & 1)*4+(#a_01_14  & 1)*3) >=16
 
}
rule Backdoor_Win32_Riprova_5{
	meta:
		description = "Backdoor:Win32/Riprova,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 13 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 6e 65 73 73 69 6f 6e 65 20 50 72 65 64 65 66 69 6e 69 74 61 } //4 Connessione Predefinita
		$a_01_1 = {43 6c 69 63 63 61 6e 64 6f 20 53 49 20 73 61 72 61 69 20 63 6f 6c 6c 65 67 61 74 6f 20 61 20 74 72 65 63 65 6e 74 6f } //4 Cliccando SI sarai collegato a trecento
		$a_01_2 = {65 75 72 6f 63 65 6e 74 20 61 6c 20 6d 69 6e 75 74 6f 20 65 20 6e 61 76 69 67 68 65 72 61 69 20 61 6c 6c 27 69 6e 74 65 72 6e 6f 20 64 65 69 20 63 6f 6e 74 65 6e 75 74 69 } //4 eurocent al minuto e navigherai all'interno dei contenuti
		$a_01_3 = {54 69 20 73 65 69 20 64 69 73 63 6f 6e 6e 65 73 73 6f 2c 20 76 75 6f 69 20 72 69 63 6f 6c 6c 65 67 61 72 74 69 20 3f } //3 Ti sei disconnesso, vuoi ricollegarti ?
		$a_01_4 = {4e 6f 6e 20 65 27 20 70 6f 73 73 69 62 69 6c 65 20 70 72 6f 63 65 64 65 72 65 } //1 Non e' possibile procedere
		$a_02_5 = {6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 5a 6f 6e 65 4d 61 70 5c 44 6f 6d 61 69 6e 73 5c [0-18] 5c 77 77 77 00 } //5
		$a_01_6 = {61 72 63 68 69 76 69 6f 73 65 78 2e 6e 65 74 } //3 archiviosex.net
		$a_01_7 = {73 65 78 76 69 64 65 6f 70 72 6f 2e 63 6f 6d } //3 sexvideopro.com
		$a_01_8 = {73 6e 70 72 74 7a } //3 snprtz
		$a_01_9 = {52 69 70 72 6f 76 61 2e 2e 2e 00 25 64 00 } //10
		$a_01_10 = {64 69 61 6c 6e 6f 00 } //2
		$a_01_11 = {2f 63 63 52 61 6e 64 6f 6d 2f 3f } //4 /ccRandom/?
		$a_01_12 = {2f 6d 65 6d 62 65 72 73 2f 69 6e 64 65 78 32 2e 70 68 70 3f } //4 /members/index2.php?
		$a_02_13 = {2e 6c 6e 6b 00 [0-30] 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c 00 } //4
		$a_01_14 = {62 75 74 74 6f 6e 00 53 49 00 4e 4f 00 54 61 68 6f 6d 61 00 } //2 畢瑴湯匀I低吀桡浯a
		$a_01_15 = {69 73 64 6e 00 00 00 00 6d 6f 64 65 6d 00 00 } //3
		$a_01_16 = {52 61 73 48 61 6e 67 55 70 41 } //1 RasHangUpA
		$a_01_17 = {52 61 73 44 69 61 6c 41 } //1 RasDialA
		$a_01_18 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 53 74 61 74 75 73 41 } //1 RasGetConnectStatusA
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_02_5  & 1)*5+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*10+(#a_01_10  & 1)*2+(#a_01_11  & 1)*4+(#a_01_12  & 1)*4+(#a_02_13  & 1)*4+(#a_01_14  & 1)*2+(#a_01_15  & 1)*3+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=21
 
}