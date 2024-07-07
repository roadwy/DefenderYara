
rule TrojanDownloader_O97M_Obfuse_BUK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BUK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 0a 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 49 57 42 6e 5a 43 53 77 75 42 49 6d } //1 = Len(Join(Array(IWBnZCSwuBIm
		$a_01_3 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 61 45 6d 75 65 71 79 53 56 34 56 76 } //1 = Len(Join(Array(aEmueqySV4Vv
		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 22 71 6d 39 51 5f 69 38 41 5f 72 52 6a } //1 = Len(Join(Array("qm9Q_i8A_rRj
		$a_01_5 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 42 6f 62 68 6c 73 48 6a 63 6f 79 38 } //1 = Len(Join(Array(BobhlsHjcoy8
		$a_01_6 = {3d 20 4e 65 49 6b 4c 49 6f 51 49 64 75 64 2e 72 54 39 79 6b 5f 69 33 56 5f 70 56 6e 66 } //1 = NeIkLIoQIdud.rT9yk_i3V_pVnf
		$a_01_7 = {3d 20 41 6b 73 57 34 52 6e 6a 30 2e 4e 39 53 45 44 51 50 45 68 63 5a 6e } //1 = AksW4Rnj0.N9SEDQPEhcZn
		$a_01_8 = {3d 20 44 6e 51 46 31 5f 69 36 4b 39 2e 56 4a 64 78 35 7a 79 48 66 } //1 = DnQF1_i6K9.VJdx5zyHf
		$a_01_9 = {3d 20 4b 37 49 77 64 7a 30 35 5a 65 49 57 38 6b 38 44 2e 57 46 4f 70 35 72 4f 75 6c 73 } //1 = K7Iwdz05ZeIW8k8D.WFOp5rOuls
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=4
 
}