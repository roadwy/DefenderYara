
rule Spammer_Win32_Sasfis_A{
	meta:
		description = "Spammer:Win32/Sasfis.A,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 0e 00 00 "
		
	strings :
		$a_01_0 = {48 41 56 45 20 47 4f 4f 44 20 41 43 43 20 6c 65 74 74 65 72 } //2 HAVE GOOD ACC letter
		$a_01_1 = {25 30 34 78 25 30 38 2e 38 6c 78 24 25 30 38 2e 38 6c 78 24 25 30 38 78 40 25 73 } //2 %04x%08.8lx$%08.8lx$%08x@%s
		$a_01_2 = {67 65 74 5f 6d 78 5f 72 65 63 6f 72 64 73 3d } //2 get_mx_records=
		$a_01_3 = {45 72 72 63 6f 6e 6e } //2 Errconn
		$a_01_4 = {45 72 72 72 65 63 76 } //2 Errrecv
		$a_01_5 = {52 3a 30 68 65 6c 6f 3f } //2 R:0helo?
		$a_01_6 = {50 61 72 73 65 20 52 43 50 54 2f 4d 41 49 4c 20 46 52 4f 4d 2f 44 41 54 41 5f 44 41 54 41 2f 6f 74 68 65 72 } //2 Parse RCPT/MAIL FROM/DATA_DATA/other
		$a_01_7 = {2f 63 67 69 2d 62 69 6e 2f 6d 63 73 2e 63 67 69 } //2 /cgi-bin/mcs.cgi
		$a_01_8 = {5c 4d 53 50 72 6f 74 6f 63 6f 6c 2e 63 70 70 } //1 \MSProtocol.cpp
		$a_01_9 = {5c 77 73 68 69 70 36 } //1 \wship6
		$a_01_10 = {6d 78 73 2e 6d 61 69 6c 2e 72 75 } //1 mxs.mail.ru
		$a_01_11 = {67 2e 6d 78 2e 6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d } //1 g.mx.mail.yahoo.com
		$a_01_12 = {73 6d 74 70 2e 67 6d 61 69 6c 2e 63 6f 6d } //1 smtp.gmail.com
		$a_01_13 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4b 4d 61 69 6c 2f 31 2e 39 2e 37 } //1 User-Agent: KMail/1.9.7
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=15
 
}