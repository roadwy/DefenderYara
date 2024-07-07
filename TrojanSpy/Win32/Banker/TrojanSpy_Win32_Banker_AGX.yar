
rule TrojanSpy_Win32_Banker_AGX{
	meta:
		description = "TrojanSpy:Win32/Banker.AGX,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2e 68 74 6d 6c 26 63 6d 64 32 3d } //3 cmd.html&cmd2=
		$a_03_1 = {33 43 6c 69 63 6b 13 00 90 02 10 49 6d 61 67 65 90 00 } //3
		$a_00_2 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //3 keybd_event
		$a_01_3 = {54 23 65 6e 74 23 65 20 6e 6f 76 23 61 6d 65 23 6e 74 65 } //1 T#ent#e nov#ame#nte
		$a_01_4 = {53 65 23 6e 68 61 20 64 23 6f 20 54 6f 6b 23 65 6e 20 69 6e 76 23 } //1 Se#nha d#o Tok#en inv#
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3+(#a_00_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}