
rule TrojanDownloader_O97M_Ursnif_APD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.APD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 7a 26 69 68 6f 6d 6d 29 23 } //1 =createobject(z&ihomm)#
		$a_01_1 = {3d 76 62 61 2e 65 6e 76 69 72 6f 6e 28 28 28 6e 69 75 28 32 38 2c 32 39 29 29 29 29 26 22 5c 22 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 =vba.environ(((niu(28,29))))&"\"endfunction
		$a_01_2 = {3d 67 65 74 6f 62 6a 65 63 74 28 76 76 29 73 65 74 64 66 3d 64 64 2e 67 65 74 28 62 6e 29 73 65 74 65 72 3d 64 66 2e 63 72 65 61 74 65 } //1 =getobject(vv)setdf=dd.get(bn)seter=df.create
		$a_01_3 = {3d 67 65 74 6f 62 6a 65 63 74 28 73 69 69 29 74 66 66 3d 37 73 65 74 6a 61 6d 3d 6d 75 75 2e 67 65 74 28 72 6f 6f 29 73 65 74 61 6e 64 72 65 3d 6a 61 6d 2e 63 72 65 61 74 65 } //1 =getobject(sii)tff=7setjam=muu.get(roo)setandre=jam.create
		$a_01_4 = {2e 6f 70 65 6e 7a 26 6f 63 6d 6f 73 2c 73 6a 69 6d 6d 2c 66 61 6c 73 65 2c 7a 2c 7a } //1 .openz&ocmos,sjimm,false,z,z
		$a_01_5 = {3d 22 61 22 26 61 26 22 3a 22 26 22 68 61 22 26 62 73 65 74 64 3d 72 61 6e 67 65 28 74 29 66 6f 72 65 61 63 68 66 69 69 6e 64 2e 73 70 65 63 69 61 6c } //1 ="a"&a&":"&"ha"&bsetd=range(t)foreachfiind.special
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}