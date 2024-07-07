
rule TrojanDropper_O97M_Obfuse_RSW_MTB{
	meta:
		description = "TrojanDropper:O97M/Obfuse.RSW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 22 20 26 20 4d 65 2e 54 65 78 74 42 6f 78 32 2e 54 65 78 74 20 26 20 55 73 65 72 46 6f 72 6d 31 2e 43 61 70 74 69 6f 6e 29 } //1 CreateObject("W" & Me.TextBox2.Text & UserForm1.Caption)
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 2e 2e 5c 4d 65 65 74 69 6e 67 22 } //1 Application.StartupPath & "\..\Meeting"
		$a_01_2 = {43 61 70 74 69 6f 6e 20 26 20 4c 65 6e 28 53 6f 6d 61 29 20 26 20 22 2e 78 6d 6c 69 22 } //1 Caption & Len(Soma) & ".xmli"
		$a_01_3 = {55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 32 2e 56 61 6c 75 65 20 3d 20 22 53 63 72 69 70 74 2e 22 } //1 UserForm1.TextBox2.Value = "Script."
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}