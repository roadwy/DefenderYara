
rule VirTool_WinNT_Floxif_A{
	meta:
		description = "VirTool:WinNT/Floxif.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 6b 69 6c 6c 5c 44 72 69 76 65 72 5c 69 33 38 36 5c 4b 49 4c 4c 50 52 43 2e 70 64 62 } //1 \kill\Driver\i386\KILLPRC.pdb
		$a_01_1 = {8d 41 05 53 8a 51 02 84 d2 74 08 30 50 ff 8a 51 02 30 10 8a 50 ff 8a 18 f6 d2 f6 d3 88 50 ff 88 18 84 d2 75 04 84 db 74 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}