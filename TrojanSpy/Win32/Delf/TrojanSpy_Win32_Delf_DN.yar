
rule TrojanSpy_Win32_Delf_DN{
	meta:
		description = "TrojanSpy:Win32/Delf.DN,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 63 75 6d 65 6e 74 6f 20 65 6d 20 61 6e 65 78 6f } //01 00  Documento em anexo
		$a_01_1 = {74 69 70 6f 3d } //01 00  tipo=
		$a_01_2 = {68 6f 74 6d 61 69 6c } //01 00  hotmail
		$a_01_3 = {70 6f 73 74 2e 73 72 66 } //01 00  post.srf
		$a_01_4 = {6c 6f 67 69 6e 3f 6c 6f 67 6f 75 74 3d 31 26 2e 69 6e 74 6c 3d 62 72 26 2e 73 72 63 3d 79 6d 26 2e 70 64 3d 79 6d 5f 76 65 72 } //00 00  login?logout=1&.intl=br&.src=ym&.pd=ym_ver
	condition:
		any of ($a_*)
 
}