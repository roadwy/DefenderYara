
rule PUA_MSIL_Offergate_J_ibt{
	meta:
		description = "PUA:MSIL/Offergate.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 3d 00 7b 00 30 00 7d 00 26 00 70 00 61 00 72 00 74 00 6e 00 65 00 72 00 3d 00 7b 00 31 00 7d 00 26 00 76 00 69 00 64 00 5f 00 65 00 78 00 65 00 3d 00 39 00 39 00 26 00 76 00 69 00 73 00 69 00 74 00 5f 00 69 00 64 00 3d 00 7b 00 32 00 7d 00 26 00 75 00 74 00 6d 00 5f 00 73 00 6f 00 75 00 72 00 63 00 65 00 3d 00 7b 00 33 00 7d 00 26 00 73 00 6f 00 75 00 72 00 63 00 65 00 3d 00 70 00 61 00 63 00 6b 00 65 00 64 00 } //1 ?version={0}&partner={1}&vid_exe=99&visit_id={2}&utm_source={3}&source=packed
		$a_00_1 = {2d 00 2d 00 2d 00 42 00 45 00 47 00 49 00 4e 00 5f 00 42 00 4c 00 4f 00 42 00 2d 00 2d 00 2d 00 } //1 ---BEGIN_BLOB---
		$a_02_2 = {0a 13 09 12 09 fe 16 ?? 00 00 01 6f ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}