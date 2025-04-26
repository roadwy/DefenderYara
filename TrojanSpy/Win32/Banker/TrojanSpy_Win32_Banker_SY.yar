
rule TrojanSpy_Win32_Banker_SY{
	meta:
		description = "TrojanSpy:Win32/Banker.SY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b } //1
		$a_00_1 = {6d 61 6e 64 6f 20 62 61 69 78 61 } //1 mando baixa
		$a_00_2 = {53 45 4e 48 41 3d } //1 SENHA=
		$a_00_3 = {70 69 63 61 73 61 63 68 65 63 6b } //1 picasacheck
		$a_00_4 = {2e 63 6f 6d 2e 62 72 } //1 .com.br
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}