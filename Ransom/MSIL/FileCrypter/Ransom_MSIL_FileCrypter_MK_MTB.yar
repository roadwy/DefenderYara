
rule Ransom_MSIL_FileCrypter_MK_MTB{
	meta:
		description = "Ransom:MSIL/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {52 61 6e 73 6f 6d 42 6c 6f 78 2e 65 78 65 } //RansomBlox.exe  1
		$a_80_1 = {52 61 6e 73 6f 6d 42 6c 6f 78 2e 50 72 6f 70 65 72 74 69 65 73 } //RansomBlox.Properties  1
		$a_80_2 = {6a 61 65 6d 69 6e 31 35 30 38 } //jaemin1508  1
		$a_80_3 = {24 38 33 61 39 38 63 31 31 2d 35 39 62 38 2d 34 63 62 35 2d 38 31 36 33 2d 62 63 62 39 35 36 30 63 39 63 37 30 } //$83a98c11-59b8-4cb5-8163-bcb9560c9c70  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule Ransom_MSIL_FileCrypter_MK_MTB_2{
	meta:
		description = "Ransom:MSIL/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 65 77 61 72 65 } //1 Ransomeware
		$a_81_1 = {68 61 63 6b 65 72 6d 74 63 32 6b 40 69 6e 64 69 61 2e 63 6f 6d } //1 hackermtc2k@india.com
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your file has been encrypted
		$a_81_3 = {59 6f 75 20 6f 6e 6c 79 20 68 61 76 65 20 61 62 6f 75 74 20 32 20 64 61 79 73 20 74 6f 20 73 65 6e 64 20 6d 6f 6e 65 79 20 28 35 30 30 4b 29 20 6f 72 20 79 6f 75 72 20 66 69 6c 65 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 } //1 You only have about 2 days to send money (500K) or your file will be lost
		$a_81_4 = {57 61 6e 61 43 72 79 20 46 61 6b 65 2e 69 6e 69 } //1 WanaCry Fake.ini
		$a_81_5 = {68 74 74 70 73 3a 2f 2f 79 6c 68 73 61 6b 78 75 73 6e 6a 61 62 6c 7a 71 79 74 6e 73 64 6d 72 72 70 74 30 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 2f 72 61 6d 73 6f 6d 2e 70 68 70 } //1 https://ylhsakxusnjablzqytnsdmrrpt0.000webhostapp.com/ramsom.php
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}
rule Ransom_MSIL_FileCrypter_MK_MTB_3{
	meta:
		description = "Ransom:MSIL/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0c 00 00 "
		
	strings :
		$a_81_0 = {70 61 79 6c 6f 61 64 } //1 payload
		$a_81_1 = {57 54 53 5f 43 55 52 52 45 4e 54 5f 53 45 52 56 45 52 5f 48 41 4e 44 4c 45 } //1 WTS_CURRENT_SERVER_HANDLE
		$a_81_2 = {57 54 53 51 75 65 72 79 53 65 73 73 69 6f 6e 49 6e 66 6f 72 6d 61 74 69 6f 6e 57 } //1 WTSQuerySessionInformationW
		$a_81_3 = {53 65 6c 66 44 65 73 74 72 6f 79 } //1 SelfDestroy
		$a_81_4 = {53 65 73 73 69 6f 6e 49 64 } //1 SessionId
		$a_81_5 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //1 Microsoft\Windows\Start Menu\Programs\Startup
		$a_81_6 = {5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 \svchost.exe
		$a_81_7 = {54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d } //1 TASKKILL /F /IM
		$a_81_8 = {2f 43 20 6b 69 6c 6c 6d 65 2e 62 61 74 20 3e 3e 20 4e 55 4c } //1 /C killme.bat >> NUL
		$a_81_9 = {62 6f 74 5f 74 6f 6b 65 6e 3d } //1 bot_token=
		$a_81_10 = {4d 61 6c 77 61 72 65 20 45 78 63 75 74 65 64 } //1 Malware Excuted
		$a_81_11 = {2e 41 4d 4a 49 58 49 55 53 } //1 .AMJIXIUS
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=10
 
}
rule Ransom_MSIL_FileCrypter_MK_MTB_4{
	meta:
		description = "Ransom:MSIL/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_81_0 = {62 61 74 63 68 2e 62 61 74 } //1 batch.bat
		$a_81_1 = {2e 7a 33 62 61 63 6b } //1 .z3back
		$a_81_2 = {44 65 63 72 79 70 74 65 64 3a } //1 Decrypted:
		$a_81_3 = {2e 7a 33 65 6e 63 } //1 .z3enc
		$a_81_4 = {5c 44 65 73 6b 74 6f 70 5c 53 61 6e 64 62 6f 78 } //1 \Desktop\Sandbox
		$a_81_5 = {4f 6f 70 73 21 20 59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 Oops! Your files have been encrypted!
		$a_81_6 = {49 66 20 79 6f 75 20 63 6c 6f 73 65 20 74 68 69 73 20 77 69 6e 64 6f 77 2c 20 61 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 } //1 If you close this window, all your data will be lost
		$a_81_7 = {5c 6b 65 79 2e 74 78 74 } //1 \key.txt
		$a_81_8 = {5c 69 76 2e 74 78 74 } //1 \iv.txt
		$a_81_9 = {43 75 72 72 65 6e 74 6c 79 20 79 6f 75 20 63 61 6e 20 64 65 63 72 79 70 74 20 31 30 20 66 69 6c 65 } //1 Currently you can decrypt 10 file
		$a_81_10 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=11
 
}
rule Ransom_MSIL_FileCrypter_MK_MTB_5{
	meta:
		description = "Ransom:MSIL/FileCrypter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5f 72 65 61 64 6d 65 2e 74 78 74 } //1 _readme.txt
		$a_81_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 6c 69 6b 65 20 70 68 6f 74 6f 73 2c 20 64 61 74 61 62 61 73 65 2c 20 64 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 6f 74 68 65 72 20 69 6d 70 6f 72 74 61 74 6e 74 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 74 72 6f 6e 67 65 73 74 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 75 6e 69 71 75 65 20 6b 65 79 } //1 All your files like photos, database, documents and other importatnt are encrypted with strongest encryption and unique key
		$a_81_2 = {54 68 69 73 20 73 6f 66 74 77 61 72 65 20 77 69 6c 6c 20 64 65 63 72 79 70 74 20 61 6c 6c 20 79 6f 75 72 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 This software will decrypt all your encrypted files
		$a_81_3 = {77 65 20 63 61 6e 20 64 65 63 72 79 70 74 20 6f 6e 6c 79 20 31 20 66 69 6c 65 20 66 72 65 65 } //1 we can decrypt only 1 file free
		$a_81_4 = {50 72 69 63 65 20 6f 66 20 70 72 69 76 61 74 65 20 6b 65 79 20 61 6e 64 20 64 65 63 72 79 70 74 20 73 6f 66 74 77 61 72 65 20 69 73 20 37 38 30 30 24 } //1 Price of private key and decrypt software is 7800$
		$a_81_5 = {59 6f 75 72 20 50 65 72 73 6f 6e 61 6c 20 49 44 3a } //1 Your Personal ID:
		$a_81_6 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //1 SELECT * FROM Win32_OperatingSystem
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}