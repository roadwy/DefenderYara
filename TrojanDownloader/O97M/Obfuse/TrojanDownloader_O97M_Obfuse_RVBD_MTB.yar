
rule TrojanDownloader_O97M_Obfuse_RVBD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVBD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c 68 76 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 77 77 77 2e 64 2e 6d 2f 67 6a 6b 6b 68 68 68 67 2f 6b 6a 64 68 2e 22 29 } //1 specialpath+("\hv.").open"get",("h://www.d.m/gjkkhhhg/kjdh.")
		$a_01_1 = {73 70 65 63 69 61 6c 70 61 74 68 2b 28 22 5c 6d 2e 22 29 2e 6f 70 65 6e 22 67 65 74 22 2c 28 22 68 3a 2f 2f 67 68 71 2e 67 68 62 2e 2f 62 68 2f 22 29 } //1 specialpath+("\m.").open"get",("h://ghq.ghb./bh/")
		$a_01_2 = {63 68 72 28 35 30 29 2b 63 68 72 28 34 38 29 2b 63 68 72 28 34 38 29 73 65 74 77 73 68 73 68 65 6c 6c 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //2 chr(50)+chr(48)+chr(48)setwshshell=createobject("wscript.shell")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}