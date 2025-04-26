
rule TrojanDownloader_O97M_IcedID_RFSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.RFSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 75 71 6a 6f 69 78 65 2e 76 6a 6c } //1 auqjoixe.vjl
		$a_01_1 = {3d 61 72 72 61 79 28 22 33 31 22 2c 22 63 30 22 2c 22 63 32 22 2c 22 31 38 22 2c 22 30 30 22 29 23 65 6e 64 69 66 76 70 65 2c 33 32 2c 36 34 2c 30 } //1 =array("31","c0","c2","18","00")#endifvpe,32,64,0
		$a_01_2 = {3d 61 72 72 61 79 28 22 33 33 22 2c 22 63 30 22 2c 22 63 33 22 29 23 65 6c 73 65 69 66 77 69 6e 33 32 74 68 65 6e 70 3d 61 72 72 61 79 28 22 33 31 22 2c 22 63 30 22 2c 22 63 32 22 2c 22 31 38 22 2c 22 30 30 22 29 23 65 6e 64 69 66 76 70 65 2c 33 32 2c 36 34 2c 30 } //1 =array("33","c0","c3")#elseifwin32thenp=array("31","c0","c2","18","00")#endifvpe,32,64,0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}