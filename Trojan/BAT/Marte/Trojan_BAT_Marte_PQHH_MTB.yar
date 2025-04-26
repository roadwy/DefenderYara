
rule Trojan_BAT_Marte_PQHH_MTB{
	meta:
		description = "Trojan:BAT/Marte.PQHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_80_0 = {44 49 53 41 42 4c 45 5f 46 41 43 54 4f 52 59 5f 52 45 53 45 54 } //DISABLE_FACTORY_RESET  3
		$a_80_1 = {72 65 61 67 65 6e 74 63 2e 65 78 65 20 2f 64 69 73 61 62 6c 65 } //reagentc.exe /disable  2
		$a_80_2 = {44 49 53 41 42 4c 45 5f 44 45 46 45 4e 44 45 52 } //DISABLE_DEFENDER  2
		$a_80_3 = {6d 69 63 68 61 65 6c 2d 63 75 72 72 65 6e 74 6c 79 2e 67 6c 2e 61 74 2e 70 6c 79 2e 67 67 } //michael-currently.gl.at.ply.gg  1
		$a_80_4 = {66 6f 64 68 65 6c 70 65 72 2e 65 78 65 } //fodhelper.exe  1
		$a_80_5 = {53 6f 66 74 77 61 72 65 5c 43 6c 61 73 73 65 73 5c 6d 73 2d 73 65 74 74 69 6e 67 73 5c 53 68 65 6c 6c 5c 4f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //Software\Classes\ms-settings\Shell\Open\command  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=10
 
}