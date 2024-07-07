
rule TrojanDropper_O97M_Obfuse_JD_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.JD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 22 20 26 20 4b 65 72 72 6f 73 69 6e 20 26 20 44 65 72 61 20 26 20 22 2e 53 48 45 22 20 26 20 47 61 6c 61 74 29 2c 20 72 75 6e 74 2c 20 56 62 4d 65 74 68 6f 64 2c 20 53 6f 70 65 20 26 20 22 53 48 45 22 20 26 20 47 61 6c 61 74 20 26 20 22 20 57 53 22 20 26 20 4b 65 72 72 6f 73 69 6e 20 26 20 44 65 72 61 20 26 20 73 65 78 20 26 20 4e 61 78 61 50 } //1 CallByName CreateObject("WS" & Kerrosin & Dera & ".SHE" & Galat), runt, VbMethod, Sope & "SHE" & Galat & " WS" & Kerrosin & Dera & sex & NaxaP
		$a_01_1 = {3d 20 22 4a 53 22 } //1 = "JS"
		$a_01_2 = {26 20 22 5c 68 6f 6d 65 2e 74 65 78 74 3a 63 6f 6e 22 } //1 & "\home.text:con"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}