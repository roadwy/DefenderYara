
rule TrojanDropper_BAT_Deadrat_SN_MTB{
	meta:
		description = "TrojanDropper:BAT/Deadrat.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {fe 0c 05 00 fe 0c 08 00 fe 0c 05 00 fe 0c 08 00 91 fe 0c 03 00 fe 0c 08 00 91 61 9c 00 fe 0c 08 00 20 01 00 00 00 d6 fe 0e 08 00 fe 0c 08 00 fe 0c 0a 00 fe 0e 0b 00 fe 0c 0b 00 3e c0 ff ff ff } //4
		$a_01_1 = {24 64 62 39 33 36 34 65 37 2d 37 37 38 38 2d 34 63 36 34 2d 38 31 34 61 2d 32 33 63 38 31 64 62 62 38 32 65 65 } //2 $db9364e7-7788-4c64-814a-23c81dbb82ee
		$a_01_2 = {5c 53 74 75 62 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 53 74 75 62 2e 70 64 62 } //2 \Stub\obj\x86\Debug\Stub.pdb
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=8
 
}