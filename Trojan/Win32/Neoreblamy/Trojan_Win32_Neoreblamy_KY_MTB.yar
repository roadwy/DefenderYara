
rule Trojan_Win32_Neoreblamy_KY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.KY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {46 4f 52 54 52 41 4e 20 37 37 } //1 FORTRAN 77
		$a_81_1 = {6d 6c 2e 20 66 72 6f 6d 20 63 75 70 20 23 } //1 ml. from cup #
		$a_81_2 = {46 61 73 74 65 73 74 46 69 6e 67 65 72 } //1 FastestFinger
		$a_81_3 = {6d 67 69 67 71 6d 73 74 6a 73 68 77 6e 62 6c 76 76 76 77 79 71 6d 6c 67 72 6d 68 6c 69 6a 61 64 72 77 70 70 6e 61 65 69 6e 6d 67 6f 6e 6b 67 75 63 6e 79 6f 67 71 79 6c } //1 mgigqmstjshwnblvvvwyqmlgrmhlijadrwppnaeinmgonkgucnyogqyl
		$a_03_4 = {89 cb c1 e3 03 09 d3 00 dc be ?? ?? ?? ?? 66 ad 31 db 89 cb c1 e3 03 09 d3 00 dc be ?? ?? ?? ?? 66 ad 00 d4 b8 ff ff ff ff be ?? ?? ?? ?? 66 ad 00 d4 b8 ff ff ff ff be ?? ?? ?? ?? 66 ad 31 db 89 cb c1 e3 03 09 d3 00 dc } //1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}