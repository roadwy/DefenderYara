
rule Trojan_BAT_Tiny_PE_MTB{
	meta:
		description = "Trojan:BAT/Tiny.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {4a 53 63 72 69 70 74 49 6d 70 6f 72 74 } //1 JScriptImport
		$a_01_1 = {4a 53 63 72 69 70 74 50 61 63 6b 61 67 65 } //1 JScriptPackage
		$a_01_2 = {45 78 65 63 75 74 65 50 72 6f 63 65 73 73 } //1 ExecuteProcess
		$a_01_3 = {53 00 69 00 62 00 43 00 6c 00 72 00 } //1 SibClr
		$a_01_4 = {53 00 69 00 62 00 43 00 61 00 } //1 SibCa
		$a_01_5 = {2e 00 76 00 62 00 73 00 20 00 2f 00 2f 00 65 00 3a 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 2f 00 2f 00 4e 00 4f 00 4c 00 4f 00 47 00 4f 00 } //1 .vbs //e:vbscript //NOLOGO
		$a_01_6 = {3d 53 69 62 43 6c 72 2c 20 56 65 72 73 69 6f 6e 3d 36 2e 30 2e 36 2e 30 2c 20 43 75 6c 74 75 72 65 3d 6e 65 75 74 72 61 6c 2c 20 50 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d 6e 75 6c 6c } //1 =SibClr, Version=6.0.6.0, Culture=neutral, PublicKeyToken=null
		$a_01_7 = {49 53 79 73 74 65 6d 2c 20 56 65 72 73 69 6f 6e 3d 34 2e 30 2e 30 2e 30 2c 20 43 75 6c 74 75 72 65 3d 6e 65 75 74 72 61 6c 2c 20 50 75 62 6c 69 63 4b 65 79 54 6f 6b 65 6e 3d 62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 } //1 ISystem, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}