
rule Ransom_Win32_Haknata_A_rsm{
	meta:
		description = "Ransom:Win32/Haknata.A!rsm,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 12 00 00 "
		
	strings :
		$a_80_0 = {4e 4d 6f 72 65 69 72 61 } //NMoreira  1
		$a_80_1 = {2e 48 61 6b 75 6e 61 4d 61 74 61 74 61 } //.HakunaMatata  1
		$a_80_2 = {2a 62 6f 6f 74 6d 67 72 2a 20 2a 62 6f 6f 74 2a 20 2a 62 6f 6f 74 2a 20 2a 43 4f 4e 46 49 47 2e 53 59 53 2a } //*bootmgr* *boot* *boot* *CONFIG.SYS*  2
		$a_80_3 = {2a 5c 6a 61 76 61 5c 2a 20 2a 5c 54 65 61 6d 56 69 65 77 65 72 5c 2a 20 2a 5c 77 69 6e 64 6f 77 73 5c 2a } //*\java\* *\TeamViewer\* *\windows\*  2
		$a_80_4 = {3c 69 6d 67 20 73 72 63 3d 27 64 61 74 61 3a 69 6d 61 67 65 2f 67 69 66 3b 62 61 73 65 36 34 2c 52 30 6c 47 4f 44 } //<img src='data:image/gif;base64,R0lGOD  1
		$a_80_5 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 2e 55 73 69 6e 67 20 41 45 53 32 35 36 2d 62 69 74 20 65 6e 63 72 79 70 74 69 6f 6e } //All your files are encrypted.Using AES256-bit encryption  1
		$a_80_6 = {43 72 79 70 74 65 72 20 77 69 74 68 20 70 72 6f 62 6c 65 6d 73 2e 20 53 63 72 65 77 65 64 20 75 70 20 63 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2e } //Crypter with problems. Screwed up configuration.  1
		$a_80_7 = {48 75 67 73 2c 20 4e 4d 6f 72 65 69 72 61 20 43 6f 72 65 20 44 65 76 2e } //Hugs, NMoreira Core Dev.  1
		$a_80_8 = {52 65 63 6f 76 65 72 73 20 66 69 6c 65 73 20 79 61 6b 6f 2e 68 74 6d 6c } //Recovers files yako.html  1
		$a_80_9 = {73 74 61 72 74 3d 20 64 69 73 61 62 6c 65 64 } //start= disabled  1
		$a_80_10 = {43 41 4c 4c 20 20 43 68 61 6e 67 65 53 74 61 72 74 4d 6f 64 65 20 27 44 69 73 61 62 6c 65 64 27 } //CALL  ChangeStartMode 'Disabled'  1
		$a_80_11 = {42 69 74 6d 65 6e 73 73 61 67 65 73 } //Bitmenssages  1
		$a_80_12 = {67 65 74 74 69 6e 67 20 69 73 20 74 68 65 20 6b 65 79 } //getting is the key  1
		$a_80_13 = {6e 6f 74 62 61 64 62 61 74 2c 2e 62 61 74 } //notbadbat,.bat  1
		$a_80_14 = {73 75 70 65 72 6d 65 74 72 6f 69 64 72 75 6c 65 73 } //supermetroidrules  1
		$a_80_15 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 68 65 6c 6c 33 32 2e 64 6c 6c 2c 34 37 } //%SystemRoot%\System32\shell32.dll,47  1
		$a_80_16 = {43 72 79 70 74 65 72 41 70 70 3a 3a 73 5f 63 72 79 70 74 65 72 41 70 70 } //CrypterApp::s_crypterApp  1
		$a_80_17 = {69 66 20 65 78 69 73 74 20 22 25 53 22 20 67 6f 74 6f 20 57 61 69 74 41 6e 64 44 65 6c 65 74 65 } //if exist "%S" goto WaitAndDelete  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1) >=6
 
}