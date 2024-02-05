
rule Worm_Win32_Licu{
	meta:
		description = "Worm:Win32/Licu,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1c 00 21 00 00 01 00 "
		
	strings :
		$a_80_0 = {4a 61 76 69 65 72 5c 41 70 6f 6c 6f 35 } //Javier\Apolo5  01 00 
		$a_80_1 = {2e 61 6f 2e 62 72 2e 63 76 2e 6d 6f 2e 6d 7a 2e 70 74 2e 73 74 } //.ao.br.cv.mo.mz.pt.st  01 00 
		$a_80_2 = {2e 61 6d 2e 61 74 2e 64 65 2e 64 6b 2e 65 65 2e 6c 69 2e 6c 75 2e } //.am.at.de.dk.ee.li.lu.  01 00 
		$a_80_3 = {2e 63 6f 6d 2e 6e 65 74 2e 6f 72 67 2e 65 64 75 2e 67 6f 76 2e 6d 69 6c } //.com.net.org.edu.gov.mil  01 00 
		$a_80_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 52 65 63 6f 72 64 73 5c } //SOFTWARE\Microsoft\Records\  01 00 
		$a_80_5 = {46 69 6c 65 54 6f 4b 69 6c 6c } //FileToKill  01 00 
		$a_80_6 = {52 65 67 46 69 6c 65 4b 69 6c 6c 65 64 } //RegFileKilled  01 00 
		$a_80_7 = {41 64 72 65 73 73 4c 69 73 74 } //AdressList  01 00 
		$a_80_8 = {4d 49 4d 45 2d 56 65 72 73 69 6f 6e 3a 20 31 2e 30 } //MIME-Version: 1.0  01 00 
		$a_80_9 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 6d 69 78 65 64 3b } //Content-Type: multipart/mixed;  01 00 
		$a_80_10 = {2d 2d 2d 2d 3d 5f 4e 65 78 74 50 61 72 74 5f 30 30 30 5f 30 30 30 32 5f 30 31 42 44 32 32 45 45 2e 43 31 32 39 31 44 41 30 } //----=_NextPart_000_0002_01BD22EE.C1291DA0  01 00 
		$a_80_11 = {62 6f 75 6e 64 61 72 79 3d 22 } //boundary="  01 00 
		$a_80_12 = {58 2d 50 72 69 6f 72 69 74 79 3a 20 33 } //X-Priority: 3  01 00 
		$a_80_13 = {58 2d 4d 53 4d 61 69 6c 20 2d 20 50 72 69 6f 72 69 74 79 3a 20 4e 6f 72 6d 61 6c } //X-MSMail - Priority: Normal  01 00 
		$a_80_14 = {58 2d 4d 69 6d 65 4f 4c 45 3a 20 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 } //X-MimeOLE: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX  01 00 
		$a_80_15 = {66 69 6c 65 6e 61 6d 65 3d 22 } //filename="  01 00 
		$a_80_16 = {45 73 74 6f 20 65 73 20 75 6e 20 6d 65 6e 73 61 6a 65 20 6d 75 6c 74 69 70 61 72 74 65 20 65 6e 20 66 6f 72 6d 61 74 6f 20 4d 49 4d 45 } //Esto es un mensaje multiparte en formato MIME  01 00 
		$a_80_17 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 70 6c 61 69 6e 3b } //Content-Type: text/plain;  01 00 
		$a_80_18 = {63 68 61 72 73 65 74 3d 22 78 2d 75 73 65 72 2d 64 65 66 69 6e 65 64 22 } //charset="x-user-defined"  01 00 
		$a_80_19 = {43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 38 62 69 74 } //Content-Transfer-Encoding: 8bit  01 00 
		$a_80_20 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6f 63 74 65 74 2d 73 74 72 65 61 6d 3b } //Content-Type: application/octet-stream;  01 00 
		$a_80_21 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 61 74 74 61 63 68 6d 65 6e 74 3b } //Content-Disposition: attachment;  01 00 
		$a_80_22 = {43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 62 61 73 65 36 34 } //Content-Transfer-Encoding: base64  01 00 
		$a_80_23 = {32 35 35 2e 32 35 35 2e 32 35 35 2e 32 35 35 } //255.255.255.255  01 00 
		$a_80_24 = {45 72 72 6f 72 20 73 65 74 74 69 6e 67 20 6c 69 6e 67 65 72 20 69 6e 66 6f 3a } //Error setting linger info:  01 00 
		$a_80_25 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 47 41 4d 45 53 } //c:\windows\GAMES  01 00 
		$a_80_26 = {2a 73 68 61 72 2a } //*shar*  01 00 
		$a_80_27 = {6e 65 74 20 73 68 61 72 65 20 47 41 4d 45 53 3d 63 3a 5c 77 69 6e 64 6f 77 73 5c 47 41 4d 45 53 20 2f 75 6e 6c 69 6d 69 74 65 64 } //net share GAMES=c:\windows\GAMES /unlimited  01 00 
		$a_80_28 = {63 24 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //c$\Documents and Settings\All Users\Start Menu\Programs\Startup  01 00 
		$a_80_29 = {63 24 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 41 6c 6c 20 55 73 65 72 73 5c 4d 65 6e } //c$\Documents and Settings\All Users\Men  01 00 
		$a_80_30 = {49 6e 69 63 69 6f 5c 50 72 6f 67 72 61 6d 61 73 5c 49 6e 69 63 69 6f } //Inicio\Programas\Inicio  01 00 
		$a_80_31 = {63 24 5c 57 69 6e 64 6f 77 73 5c 41 6c 6c 20 55 73 65 72 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 55 70 } //c$\Windows\All Users\Start Menu\Programs\StartUp  01 00 
		$a_80_32 = {63 24 5c 57 69 6e 64 6f 77 73 5c 41 6c 6c 20 55 73 65 72 73 5c 4d 65 6e } //c$\Windows\All Users\Men  00 00 
	condition:
		any of ($a_*)
 
}