
rule TrojanDownloader_O97M_Obfuse_RVBO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 =createobject("wscript.shell")endfunction
		$a_01_1 = {61 75 74 6f 5f 63 6c 6f 73 65 28 29 6c 5f 5f 36 36 24 65 6e 64 73 75 62 } //1 auto_close()l__66$endsub
		$a_01_2 = {61 6c 6c 66 61 75 6c 74 2e 65 78 65 63 78 79 7a 74 2b 6c 5f 6f 34 2b 6c 5f 6f 35 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 allfault.execxyzt+l_o4+l_o5endfunction
		$a_01_3 = {6c 5f 6f 35 3d 22 70 61 73 73 2d 6e 6f 70 2d 77 31 3b 69 27 65 27 78 28 69 77 72 28 27 68 74 74 70 } //1 l_o5="pass-nop-w1;i'e'x(iwr('http
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}