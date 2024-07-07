
rule Trojan_O97M_Obfuse_BO{
	meta:
		description = "Trojan:O97M/Obfuse.BO,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
		$a_03_1 = {3d 20 53 68 61 70 65 73 28 90 02 20 29 90 00 } //5
		$a_00_2 = {56 42 41 2e 53 68 65 6c 6c 25 20 } //2 VBA.Shell% 
		$a_00_3 = {49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c 28 } //2 Interaction.Shell(
		$a_00_4 = {2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 20 2b 20 } //1 .TextFrame.TextRange.Text + 
		$a_01_5 = {2e 54 65 78 74 46 72 61 6d 65 2e 43 6f 6e 74 61 69 6e 69 6e 67 52 61 6e 67 65 } //2 .TextFrame.ContainingRange
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*5+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_01_5  & 1)*2) >=9
 
}