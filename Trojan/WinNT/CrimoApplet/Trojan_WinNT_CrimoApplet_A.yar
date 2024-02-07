
rule Trojan_WinNT_CrimoApplet_A{
	meta:
		description = "Trojan:WinNT/CrimoApplet.A,SIGNATURE_TYPE_JAVAHSTR_EXT,0e 00 0d 00 0c 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 61 76 61 2f 6e 65 74 2f 55 52 4c } //01 00  java/net/URL
		$a_00_1 = {6a 61 76 61 2f 75 74 69 6c 2f 6c 6f 67 67 69 6e 67 2f 4c 6f 67 67 65 72 } //01 00  java/util/logging/Logger
		$a_00_2 = {6a 61 76 61 2f 61 70 70 6c 65 74 2f 41 70 70 6c 65 74 43 6f 6e 74 65 78 74 } //01 00  java/applet/AppletContext
		$a_00_3 = {6a 61 76 61 2f 69 6f 2f 49 4f 45 78 63 65 70 74 69 6f 6e } //01 00  java/io/IOException
		$a_00_4 = {6a 61 76 61 2f 62 65 61 6e 73 2f 45 78 70 72 65 73 73 69 6f 6e } //01 00  java/beans/Expression
		$a_01_5 = {67 65 74 4c 6f 67 67 65 72 } //01 00  getLogger
		$a_01_6 = {73 68 6f 77 44 6f 63 75 6d 65 6e 74 } //05 00  showDocument
		$a_03_7 = {b8 9a 2a b6 bb 59 90 02 12 b7 3a 2a b6 19 b9 90 00 } //05 00 
		$a_01_8 = {12 b6 b6 12 b6 b6 4d } //01 00 
		$a_01_9 = {4a 53 4d 5f 6f 6e 4c 6f 61 64 46 61 69 6c } //01 00  JSM_onLoadFail
		$a_03_10 = {53 52 45 53 55 4c 4c 41 90 02 05 45 4c 49 46 4f 52 50 90 00 } //05 00 
		$a_01_11 = {41 64 61 6f 4c 6e 6f 5f 4d 53 4a } //00 00  AdaoLno_MSJ
	condition:
		any of ($a_*)
 
}