
rule Trojan_BAT_Bingoml_RB_MTB{
	meta:
		description = "Trojan:BAT/Bingoml.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 61 00 77 00 2f 00 5a 00 70 00 64 00 73 00 50 00 6a 00 58 00 56 00 } //1 pastebin.com/raw/ZpdsPjXV
		$a_01_1 = {52 62 78 5f 74 6f 6f 6c 5f 78 6d 61 73 74 65 72 70 5c 52 62 78 5f 74 6f 6f 6c 5f 78 6d 61 73 74 65 72 70 5c 6f 62 6a 5c 44 65 62 75 67 5c 52 62 78 5f 74 6f 6f 6c 5f 78 6d 61 73 74 65 72 70 2e 70 64 62 } //1 Rbx_tool_xmasterp\Rbx_tool_xmasterp\obj\Debug\Rbx_tool_xmasterp.pdb
		$a_01_2 = {24 39 30 61 62 37 37 30 37 2d 39 31 30 39 2d 34 37 61 66 2d 39 63 38 39 2d 63 66 38 39 35 34 33 66 30 34 62 31 } //1 $90ab7707-9109-47af-9c89-cf89543f04b1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}