
rule Worm_Win32_Levona_E{
	meta:
		description = "Worm:Win32/Levona.E,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 6f 72 72 79 2c 20 53 61 79 61 20 6c 75 70 61 20 6e 69 68 20 3a 29 } //1 Sorry, Saya lupa nih :)
		$a_01_1 = {31 37 20 54 61 68 75 6e 20 4b 65 61 74 61 73 } //1 17 Tahun Keatas
		$a_00_2 = {4e 6f 76 61 2e 73 63 72 } //1 Nova.scr
		$a_00_3 = {41 56 50 33 32 2e 45 58 45 } //1 AVP32.EXE
		$a_00_4 = {5a 41 4e 41 52 4b 41 4e 44 2e 45 58 45 } //1 ZANARKAND.EXE
		$a_00_5 = {4d 41 50 49 53 65 6e 64 4d 61 69 6c } //1 MAPISendMail
		$a_00_6 = {52 65 6e 6f 76 61 5f 45 6d 69 72 61 } //1 Renova_Emira
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}