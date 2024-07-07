
rule VirTool_BAT_Injector_VH_bit{
	meta:
		description = "VirTool:BAT/Injector.VH!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 5a 00 51 00 52 00 32 00 37 00 59 00 34 00 33 00 73 00 44 00 62 00 4f 00 4e 00 39 00 37 00 4b 00 4f 00 4a 00 47 00 41 00 67 00 3d 00 3d 00 2e 00 62 00 61 00 74 00 } //1 FZQR27Y43sDbON97KOJGAg==.bat
		$a_01_1 = {47 00 53 00 44 00 47 00 53 00 44 00 47 00 53 00 44 00 47 00 53 00 44 00 } //1 GSDGSDGSDGSD
		$a_01_2 = {23 00 6e 00 73 00 64 00 66 00 66 00 64 00 73 00 70 00 23 00 24 00 24 00 24 00 2e 00 65 00 78 00 65 00 24 00 24 00 24 00 } //1 #nsdffdsp#$$$.exe$$$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}