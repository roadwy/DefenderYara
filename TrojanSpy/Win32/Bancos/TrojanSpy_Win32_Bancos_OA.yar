
rule TrojanSpy_Win32_Bancos_OA{
	meta:
		description = "TrojanSpy:Win32/Bancos.OA,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 62 53 65 67 2e 65 78 65 } //1 BbSeg.exe
		$a_01_1 = {64 6f 77 6e 6c 30 61 64 2e 74 72 61 63 6b } //1 downl0ad.track
		$a_01_2 = {5c 66 65 63 68 61 72 2e 68 74 6d 6c } //1 \fechar.html
		$a_01_3 = {67 62 70 6b 6d 2e 73 79 73 } //1 gbpkm.sys
		$a_01_4 = {42 00 61 00 6e 00 63 00 6f 00 20 00 64 00 6f 00 20 00 42 00 72 00 61 00 73 00 69 00 6c 00 } //1 Banco do Brasil
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}