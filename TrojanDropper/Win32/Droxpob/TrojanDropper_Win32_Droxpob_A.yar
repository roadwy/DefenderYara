
rule TrojanDropper_Win32_Droxpob_A{
	meta:
		description = "TrojanDropper:Win32/Droxpob.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 43 48 45 4c 49 43 4f 50 54 45 52 46 54 57 } //1 RCHELICOPTERFTW
		$a_01_1 = {61 74 74 72 69 62 20 2b 68 20 43 3a 5c 54 45 4d 50 5c 79 74 6d 70 } //1 attrib +h C:\TEMP\ytmp
		$a_01_2 = {65 63 68 6f 20 78 6d 6c 68 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 73 2f 30 74 70 38 67 72 62 78 68 68 61 75 30 61 79 2f 63 6c 69 63 6b 65 72 2e 70 79 77 3f 64 6c 3d 31 22 2c 20 46 61 6c 73 65 20 3e 3e 20 70 79 74 68 6f 6e 2e 76 62 73 } //1 echo xmlhttp.Open "GET", "https://www.dropbox.com/s/0tp8grbxhhau0ay/clicker.pyw?dl=1", False >> python.vbs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}