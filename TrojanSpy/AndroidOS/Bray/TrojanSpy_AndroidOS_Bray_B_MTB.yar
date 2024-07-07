
rule TrojanSpy_AndroidOS_Bray_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 42 6f 74 46 77 41 48 47 51 73 51 45 44 45 54 47 67 73 3d } //1 FBotFwAHGQsQEDETGgs=
		$a_01_1 = {46 42 6f 74 42 77 63 47 41 44 45 58 42 51 41 42 44 52 55 3d } //1 FBotBwcGADEXBQABDRU=
		$a_01_2 = {46 41 38 63 45 44 77 45 42 43 77 4b 4d 77 73 45 47 77 67 4a 47 52 45 62 53 53 51 2b 4a 68 41 48 43 6c 56 48 } //1 FA8cEDwEBCwKMwsEGwgJGREbSSQ+JhAHClVH
		$a_01_3 = {42 41 55 63 41 41 6f 48 41 31 52 63 53 78 30 4c 47 30 67 44 48 42 59 41 45 51 3d 3d } //1 BAUcAAoHA1RcSx0LG0gDHBYAEQ==
		$a_01_4 = {46 41 38 63 45 41 77 47 47 52 6f 53 42 78 6f 3d } //1 FA8cEAwGGRoSBxo=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}