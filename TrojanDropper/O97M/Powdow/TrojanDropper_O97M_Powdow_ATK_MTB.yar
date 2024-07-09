
rule TrojanDropper_O97M_Powdow_ATK_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.ATK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 2e 6a 73 65 22 } //1 & ".jse"
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 22 } //1 = Environ("TEMP") & "\"
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4d 69 64 28 4d 65 6d 6f 72 79 2e 63 6d 64 2e 43 61 70 74 69 6f 6e 2c } //1 CreateObject(Mid(Memory.cmd.Caption,
		$a_01_3 = {54 65 6d 70 20 3d 20 4d 69 64 28 54 65 6d 70 2c 20 49 6e 53 74 72 28 54 65 6d 70 2c 20 22 5c 22 29 } //1 Temp = Mid(Temp, InStr(Temp, "\")
		$a_03_4 = {50 72 69 6e 74 20 23 [0-02] 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}