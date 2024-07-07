
rule PWS_Win32_Amadey_GG_MTB{
	meta:
		description = "PWS:Win32/Amadey.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 09 00 00 "
		
	strings :
		$a_80_0 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 55 70 6c 6f 61 64 6f 72 } //User-Agent: Uploador  10
		$a_80_1 = {73 63 72 3d 75 70 } //scr=up  1
		$a_80_2 = {78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 25 2e 32 78 } //x%.2x%.2x%.2x%.2x%.2x%.2x  1
		$a_80_3 = {6e 61 6d 65 3d 22 64 61 74 61 22 } //name="data"  1
		$a_80_4 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 } //Content-Disposition: form-data  1
		$a_80_5 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d } //Content-Type: application/octet-stream  1
		$a_80_6 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 66 6f 72 6d 2d 64 61 74 61 } //Content-Type: multipart/form-data  1
		$a_80_7 = {43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 4b 65 65 70 2d 41 6c 69 76 65 } //Connection: Keep-Alive  1
		$a_80_8 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a } //Content-Length:  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=16
 
}
rule PWS_Win32_Amadey_GG_MTB_2{
	meta:
		description = "PWS:Win32/Amadey.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0e 00 00 "
		
	strings :
		$a_80_0 = {4f 75 74 6c 6f 6f 6b } //Outlook  1
		$a_80_1 = {49 4d 41 50 20 50 61 73 73 77 6f 72 64 } //IMAP Password  1
		$a_80_2 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 } //POP3 Password  1
		$a_80_3 = {3c 70 61 73 73 77 6f 72 64 3e } //<password>  1
		$a_80_4 = {3c 50 61 73 73 20 65 6e 63 6f 64 69 6e 67 3d 22 62 61 73 65 36 34 22 3e } //<Pass encoding="base64">  1
		$a_80_5 = {50 69 64 67 69 6e } //Pidgin  1
		$a_80_6 = {5c 46 69 6c 65 5a 69 6c 6c 61 5c 73 69 74 65 6d 61 6e 61 67 65 72 2e 78 6d 6c } //\FileZilla\sitemanager.xml  1
		$a_80_7 = {5c 2e 70 75 72 70 6c 65 5c 61 63 63 6f 75 6e 74 73 2e 78 6d 6c } //\.purple\accounts.xml  1
		$a_80_8 = {5c 57 63 78 5f 66 74 70 2e 69 6e 69 } //\Wcx_ftp.ini  1
		$a_80_9 = {5c 77 69 6e 73 63 70 2e 69 6e 69 } //\winscp.ini  1
		$a_80_10 = {52 65 61 6c 56 4e 43 } //RealVNC  1
		$a_80_11 = {54 69 67 68 74 56 4e 43 } //TightVNC  1
		$a_80_12 = {50 61 73 73 77 6f 72 64 3d } //Password=  1
		$a_80_13 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a } //Content-Length:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1) >=10
 
}
rule PWS_Win32_Amadey_GG_MTB_3{
	meta:
		description = "PWS:Win32/Amadey.GG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 95 ec fe ff ff 8b 95 ec fe ff ff 0f b6 84 15 f8 fe ff ff 8b 8d f0 fe ff ff 0f b6 94 0d f8 fe ff ff 33 d0 89 95 d8 fd ff ff 8b 85 f0 fe ff ff 8a 8d d8 fd ff ff 88 8c 05 f8 fe ff ff 0f b6 95 d8 fd ff ff 8b 85 ec fe ff ff 0f b6 8c 05 f8 fe ff ff 33 ca 89 8d d4 fd ff ff 8b 95 ec fe ff ff 8a 85 d4 fd ff ff 88 84 15 f8 fe ff ff 0f b6 8d d4 fd ff ff 8b 95 f0 fe ff ff 0f b6 84 15 f8 fe ff ff 33 c1 8b 8d f0 fe ff ff 88 84 0d f8 fe ff ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}