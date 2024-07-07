
rule Trojan_O97M_SLoad_RDA_MTB{
	meta:
		description = "Trojan:O97M/SLoad.RDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 68 65 72 62 65 72 2e 64 65 2f 61 6e 64 65 72 65 2f 62 65 61 6e 2e 65 78 65 } //2 ://www.herber.de/andere/bean.exe
		$a_01_1 = {44 6f 77 6e 6c } //2 Downl
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}