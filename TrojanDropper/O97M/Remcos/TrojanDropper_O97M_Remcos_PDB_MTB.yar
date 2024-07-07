
rule TrojanDropper_O97M_Remcos_PDB_MTB{
	meta:
		description = "TrojanDropper:O97M/Remcos.PDB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 6a 74 74 6f 63 3d 74 79 71 6c 68 6b 75 28 29 2b 22 22 2b 67 31 28 29 2b 67 32 28 29 2b 22 2d 22 2b 67 33 28 29 2b 67 34 28 29 70 61 74 68 79 3d } //1 &jttoc=tyqlhku()+""+g1()+g2()+"-"+g3()+g4()pathy=
		$a_01_1 = {62 64 66 64 66 3d 74 38 67 30 66 2e 6f 70 65 6e 28 76 30 64 66 2b 22 5c 63 69 74 77 7a 2e 62 61 74 22 29 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 72 65 76 28 73 29 64 69 6d 70 66 6f 72 70 3d 6c 65 6e 28 73 29 74 6f 31 73 74 65 70 2d 31 72 65 76 3d 72 65 76 26 6d 69 64 28 73 2c 70 2c 31 29 6e 65 78 74 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 69 6b 66 77 71 28 29 } //1 bdfdf=t8g0f.open(v0df+"\citwz.bat")endfunctionfunctionrev(s)dimpforp=len(s)to1step-1rev=rev&mid(s,p,1)nextendfunctionfunctionikfwq()
		$a_01_2 = {6f 6d 77 6d 6c 66 3d 70 61 74 68 79 2b 22 5c 63 69 74 77 7a 2e 62 61 74 22 27 79 6f 75 63 61 6e 73 70 65 63 69 66 79 68 65 72 65 74 68 65 74 65 78 74 66 69 6c 65 6e 61 6d 65 79 6f 75 77 61 6e 74 74 6f 63 72 65 61 74 65 } //1 omwmlf=pathy+"\citwz.bat"'youcanspecifyherethetextfilenameyouwanttocreate
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}