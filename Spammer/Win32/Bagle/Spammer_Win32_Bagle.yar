
rule Spammer_Win32_Bagle{
	meta:
		description = "Spammer:Win32/Bagle,SIGNATURE_TYPE_PEHSTR,24 00 20 00 27 00 00 "
		
	strings :
		$a_01_0 = {61 6c 72 65 61 64 79 41 72 69 61 6c } //1 alreadyArial
		$a_01_1 = {66 69 6c 65 73 79 73 2c 20 66 69 6c 65 74 78 74 2c 20 67 65 74 6e 61 6d 65 2c 20 70 61 74 68 2c 20 74 65 78 74 66 69 6c 65 2c } //1 filesys, filetxt, getname, path, textfile,
		$a_01_2 = {2e 57 72 69 74 65 28 63 68 72 28 61 28 69 29 29 29 } //1 .Write(chr(a(i)))
		$a_01_3 = {22 20 26 20 76 62 63 72 6c 66 } //2 " & vbcrlf
		$a_01_4 = {48 45 4c 4f 20 25 73 2e 6e 65 74 } //1 HELO %s.net
		$a_01_5 = {48 45 4c 4f 20 25 73 2e 63 6f 6d } //1 HELO %s.com
		$a_01_6 = {48 45 4c 4f 20 25 73 2e 6f 72 67 } //1 HELO %s.org
		$a_01_7 = {4d 41 49 4c 20 46 52 4f 4d 3a 3c 25 73 3e } //1 MAIL FROM:<%s>
		$a_01_8 = {52 43 50 54 20 54 4f 3a 3c 25 73 3e } //1 RCPT TO:<%s>
		$a_01_9 = {40 73 6f 6d 65 77 68 65 72 65 } //1 @somewhere
		$a_01_10 = {46 72 6f 6d 3a 20 22 25 73 22 20 3c 25 73 3e } //1 From: "%s" <%s>
		$a_01_11 = {53 75 62 6a 65 63 74 3a 20 25 73 } //1 Subject: %s
		$a_01_12 = {4d 65 73 73 61 67 65 2d 49 44 3a 20 3c 25 73 25 73 3e } //1 Message-ID: <%s%s>
		$a_01_13 = {62 6f 75 6e 64 61 72 79 3d 22 2d 2d 2d 2d 2d 2d 2d 2d 25 73 } //1 boundary="--------%s
		$a_01_14 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 25 73 3b 20 6e 61 6d 65 3d 22 25 73 2e 25 73 } //1 Content-Type: %s; name="%s.%s
		$a_01_15 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 61 74 74 61 63 68 6d 65 6e 74 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 25 73 2e 25 73 } //1 Content-Disposition: attachment; filename="%s.%s
		$a_01_16 = {3c 69 6d 67 20 73 72 63 3d 22 63 69 64 3a 25 73 2e 25 73 22 3e 3c 62 72 3e } //1 <img src="cid:%s.%s"><br>
		$a_01_17 = {50 61 73 73 77 6f 72 64 3a 20 25 73 } //1 Password: %s
		$a_01_18 = {50 61 73 73 77 6f 72 64 20 2d 20 25 73 } //1 Password - %s
		$a_01_19 = {52 65 3a 20 4d 73 67 } //1 Re: Msg
		$a_01_20 = {52 65 3a 20 54 68 61 6e 6b } //1 Re: Thank
		$a_01_21 = {52 65 3a 20 44 6f 63 75 6d 65 6e 74 } //1 Re: Document
		$a_01_22 = {52 65 3a 20 49 6e 63 6f 6d 69 6e 67 } //1 Re: Incoming
		$a_01_23 = {52 45 3a 20 4d 65 73 73 61 67 65 } //1 RE: Message
		$a_01_24 = {45 6e 63 72 79 70 74 65 64 20 64 6f 63 75 6d 65 6e 74 } //1 Encrypted document
		$a_01_25 = {52 65 61 64 20 74 68 65 20 61 74 74 61 63 68 2e 3c 62 72 3e 3c 62 72 3e } //1 Read the attach.<br><br>
		$a_01_26 = {59 6f 75 72 20 66 69 6c 65 20 69 73 20 61 74 74 61 63 68 65 64 2e 3c 62 72 3e 3c 62 72 3e } //1 Your file is attached.<br><br>
		$a_01_27 = {64 65 74 61 69 6c 73 2e 3c 62 72 3e 3c 62 72 3e } //1 details.<br><br>
		$a_01_28 = {66 69 6c 65 2e 3c 62 72 3e 3c 62 72 3e } //1 file.<br><br>
		$a_01_29 = {3c 62 72 3e 46 6f 72 20 73 65 63 75 72 69 74 79 20 } //1 <br>For security 
		$a_01_30 = {70 61 73 73 77 6f 72 64 20 3c 69 6d 67 20 73 72 63 3d 22 63 69 64 3a 25 73 2e 25 73 22 3e } //1 password <img src="cid:%s.%s">
		$a_01_31 = {53 6b 79 6e 65 74 } //1 Skynet
		$a_01_32 = {5a 6f 6e 65 20 4c 61 62 73 20 43 6c 69 65 6e 74 } //1 Zone Labs Client
		$a_01_33 = {41 6e 74 69 76 69 72 75 73 } //1 Antivirus
		$a_01_34 = {46 69 72 65 77 61 6c 6c 20 53 65 72 76 69 63 65 } //1 Firewall Service
		$a_01_35 = {54 69 6e 79 20 41 56 } //1 Tiny AV
		$a_01_36 = {53 79 73 4d 6f 6e 58 50 } //1 SysMonXP
		$a_01_37 = {4e 6f 72 74 6f 6e 20 } //1 Norton 
		$a_01_38 = {4b 61 73 70 65 72 73 6b 79 } //1 Kaspersky
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1+(#a_01_24  & 1)*1+(#a_01_25  & 1)*1+(#a_01_26  & 1)*1+(#a_01_27  & 1)*1+(#a_01_28  & 1)*1+(#a_01_29  & 1)*1+(#a_01_30  & 1)*1+(#a_01_31  & 1)*1+(#a_01_32  & 1)*1+(#a_01_33  & 1)*1+(#a_01_34  & 1)*1+(#a_01_35  & 1)*1+(#a_01_36  & 1)*1+(#a_01_37  & 1)*1+(#a_01_38  & 1)*1) >=32
 
}