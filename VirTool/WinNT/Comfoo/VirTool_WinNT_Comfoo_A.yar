
rule VirTool_WinNT_Comfoo_A{
	meta:
		description = "VirTool:WinNT/Comfoo.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c1 83 e8 05 89 45 08 a1 ?? ?? ?? ?? c6 00 e9 40 52 8b 55 08 89 10 5a 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
		$a_00_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 44 00 65 00 76 00 43 00 74 00 72 00 6c 00 4b 00 72 00 6e 00 6c 00 } //1 \Device\DevCtrlKrnl
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}