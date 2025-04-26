
rule TrojanSpy_Win32_Delf_ZK{
	meta:
		description = "TrojanSpy:Win32/Delf.ZK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 6c 65 65 78 7c 2d 4c 63 61 60 6d 64 6c 75 28 51 51 38 } //1 Paleex|-Lca`mdlu(QQ8
		$a_01_1 = {41 56 50 2e 41 6c 65 72 74 44 69 61 6c 6f 67 } //1 AVP.AlertDialog
		$a_01_2 = {4b 61 79 69 74 6c 61 72 27 69 20 47 65 6c 64 69 2e } //1 Kayitlar'i Geldi.
		$a_00_3 = {5c 72 61 73 5c 73 79 73 6b 72 6e 6c 2e 73 79 73 } //1 \ras\syskrnl.sys
		$a_01_4 = {65 69 61 6a 55 63 60 6a 6f 63 75 45 6e 79 67 62 7c 2c 62 65 62 } //1 eiajUc`jocuEnygb|,beb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}