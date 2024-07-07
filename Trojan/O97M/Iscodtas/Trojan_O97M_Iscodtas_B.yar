
rule Trojan_O97M_Iscodtas_B{
	meta:
		description = "Trojan:O97M/Iscodtas.B,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_02_0 = {73 63 68 74 61 73 6b 73 90 02 10 20 2f 63 72 65 61 74 65 20 90 00 } //1
		$a_00_1 = {4d 73 67 42 6f 78 20 } //-100 MsgBox 
		$a_00_2 = {4d 73 67 42 6f 78 28 } //-100 MsgBox(
		$a_00_3 = {74 78 74 20 3e 3e 67 61 6c 69 73 74 2e 74 78 74 } //-100 txt >>galist.txt
		$a_00_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 5f 41 70 70 6c 5c 5a 31 34 37 5c 62 61 74 5c 41 41 54 65 69 6b 69 52 65 62 6f 6f 74 2e 62 61 74 } //-100 C:\Program Files\D_Appl\Z147\bat\AATeikiReboot.bat
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*-100+(#a_00_2  & 1)*-100+(#a_00_3  & 1)*-100+(#a_00_4  & 1)*-100) >=1
 
}