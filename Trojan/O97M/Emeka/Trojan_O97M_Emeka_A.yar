
rule Trojan_O97M_Emeka_A{
	meta:
		description = "Trojan:O97M/Emeka.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 41 70 70 64 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 57 6f 72 6c 64 2e 62 61 74 } //1 \Appdata\Local\Microsoft\Office\World.bat
		$a_02_1 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 90 02 02 3a 2f 2f 90 02 30 2f 62 61 74 33 2e 74 78 74 22 2c 20 46 61 6c 73 65 90 00 } //1
		$a_00_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 66 70 46 6f 6e 74 2c 20 32 } //1 .savetofile fpFont, 2
		$a_00_3 = {6f 62 6a 57 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 objW.Get("Win32_ProcessStartup")
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}