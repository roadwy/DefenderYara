
rule Trojan_VBA_Obfuse_AKA_eml{
	meta:
		description = "Trojan:VBA/Obfuse.AKA!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 6a 64 65 72 65 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 } //1 Ujdere Application.StartupPath
		$a_01_1 = {20 53 65 6c 65 63 74 69 6f 6e 2e 46 69 6e 64 2e 45 78 65 63 75 74 65 20 52 65 70 6c 61 63 65 3a 3d 77 64 52 65 70 6c 61 63 65 41 6c 6c 2c 20 46 6f 72 77 61 72 64 3a 3d 54 72 75 65 2c 20 57 72 61 70 3a 3d 77 64 46 69 6e 64 43 6f 6e 74 69 6e 75 65 } //1  Selection.Find.Execute Replace:=wdReplaceAll, Forward:=True, Wrap:=wdFindContinue
		$a_01_2 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 52 65 64 66 74 79 20 26 20 22 57 53 63 22 20 26 20 52 65 64 66 74 79 20 26 20 22 72 22 20 26 20 22 22 20 26 20 22 69 70 22 20 26 20 52 65 64 66 74 79 20 26 20 22 74 2e 22 20 26 20 47 74 75 79 68 30 29 2c 20 5f } //1 CallByName CreateObject(Redfty & "WSc" & Redfty & "r" & "" & "ip" & Redfty & "t." & Gtuyh0), _
		$a_01_3 = {52 75 6e 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 5f } //1 Run", VbMethod, _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}