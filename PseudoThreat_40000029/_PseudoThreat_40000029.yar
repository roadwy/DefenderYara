
rule _PseudoThreat_40000029{
	meta:
		description = "!PseudoThreat_40000029,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 45 53 50 6c 75 67 69 6e } //1 IESPlugin
		$a_01_1 = {54 6f 6f 6c 62 61 72 57 69 6e 64 6f 77 33 32 } //1 ToolbarWindow32
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 54 6f 6f 6c 62 61 72 } //1 Software\Microsoft\Internet Explorer\Toolbar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}