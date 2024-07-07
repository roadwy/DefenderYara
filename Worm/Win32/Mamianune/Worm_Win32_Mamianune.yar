
rule Worm_Win32_Mamianune{
	meta:
		description = "Worm:Win32/Mamianune,SIGNATURE_TYPE_PEHSTR,0f 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6d 69 61 6e 75 6e 65 6e 6e 6f 6c 61 65 6c 6c 65 69 61 6f 72 61 72 64 61 64 6f 64 65 75 65 74 61 20 71 20 73 61 6d 6d 65 65 73 20 61 20 70 20 63 72 61 6c 6f 72 65 20 79 6f 20 65 72 61 20 75 20 65 20 74 69 6f 6e 65 74 61 6c 61 62 20 74 4d 41 70 69 53 79 75 6d 6f 66 69 6e 74 65 6e 65 70 65 63 65 73 65 64 75 65 67 6e 69 74 68 70 6f 62 6f 63 6f 63 61 61 64 69 72 74 72 73 61 63 72 6d 75 75 69 65 6d 61 73 73 6f 69 73 67 6f 72 6f 6e 74 20 68 6d 6f 3c 68 3c 74 3e 3c 2f 74 2f 66 2f 68 6d 6c 72 69 28 29 3d 22 65 3d 75 72 6f 67 61 69 69 72 63 63 6c 69 7b 20 7d 3c 5f 6c 65 79 78 41 63 6b 63 74 33 32 } //10 mamianunennolaelleiaorardadodeueta q sammees a p cralore yo era u e tionetalab tMApiSyumofintenepeceseduegnithpobococaadirtrsacrmuuiemassoisgoront hmo<h<t></t/f/hmlri()="e=urogaiirccli{ }<_leyxAckct32
		$a_01_1 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 6d 75 6c 74 69 70 61 72 74 2f 6d 69 78 65 64 3b 20 62 6f 75 6e 64 61 72 79 3d } //1 Content-Type: multipart/mixed; boundary=
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_3 = {6d 61 69 6c 20 66 72 6f 6d 3a 3c } //1 mail from:<
		$a_01_4 = {72 63 70 74 20 74 6f 3a 3c } //1 rcpt to:<
		$a_01_5 = {43 6f 6e 74 65 6e 74 2d 54 72 61 6e 73 66 65 72 2d 45 6e 63 6f 64 69 6e 67 3a 20 62 61 73 65 36 34 } //1 Content-Transfer-Encoding: base64
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}