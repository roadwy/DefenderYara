
rule Trojan_O97M_Obfuse_BU{
	meta:
		description = "Trojan:O97M/Obfuse.BU,SIGNATURE_TYPE_MACROHSTR_EXT,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_03_0 = {53 68 61 70 65 73 28 22 90 12 10 00 22 29 } //10
		$a_01_1 = {2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 20 2b 20 } //10 .TextFrame.TextRange.Text + 
		$a_03_2 = {2e 52 75 6e 20 [0-10] 2c } //1
		$a_03_3 = {2e 52 75 6e 21 [0-10] 2c } //1
		$a_03_4 = {2e 52 75 6e 23 [0-10] 2c } //1
		$a_01_5 = {22 6e 65 77 3a 37 32 43 32 34 44 44 35 2d 44 37 30 41 2d 34 33 38 42 2d 38 41 34 32 2d 39 38 34 32 34 42 38 38 41 46 42 38 22 20 2b 20 } //10 "new:72C24DD5-D70A-438B-8A42-98424B88AFB8" + 
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*10) >=31
 
}