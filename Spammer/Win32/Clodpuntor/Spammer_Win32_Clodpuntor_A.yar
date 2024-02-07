
rule Spammer_Win32_Clodpuntor_A{
	meta:
		description = "Spammer:Win32/Clodpuntor.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0d 00 0a 00 00 03 00 "
		
	strings :
		$a_01_0 = {52 4e 44 5f 48 45 58 } //03 00  RND_HEX
		$a_01_1 = {52 41 4e 44 53 55 42 4a } //03 00  RANDSUBJ
		$a_00_2 = {36 36 37 20 57 53 41 53 74 61 72 74 75 70 20 65 72 72 6f 72 } //03 00  667 WSAStartup error
		$a_00_3 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 22 20 65 6e 61 62 6c 65 } //01 00  netsh firewall set allowedprogram "%s" enable
		$a_01_4 = {52 45 41 4c 5f 49 50 } //01 00  REAL_IP
		$a_01_5 = {44 41 54 45 42 } //01 00  DATEB
		$a_01_6 = {46 52 4f 4d 5f 4d 58 } //01 00  FROM_MX
		$a_00_7 = {36 36 37 20 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 20 65 72 72 6f 72 } //01 00  667 gethostbyname error
		$a_00_8 = {36 36 37 25 25 32 30 67 65 74 68 6f 73 74 62 79 6e 61 6d 65 25 25 32 30 65 72 72 6f 72 } //01 00  667%%20gethostbyname%%20error
		$a_01_9 = {2d 2d 2d 2d 3d 5f 4e 65 78 74 50 61 72 74 5f 25 25 30 33 64 5f } //00 00  ----=_NextPart_%%03d_
	condition:
		any of ($a_*)
 
}