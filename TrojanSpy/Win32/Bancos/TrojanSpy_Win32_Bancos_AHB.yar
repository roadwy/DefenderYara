
rule TrojanSpy_Win32_Bancos_AHB{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 69 6e 66 65 63 74 73 2f 61 76 69 73 6f 2e 70 68 70 } //2 /infects/aviso.php
		$a_01_1 = {2f 69 6e 66 65 63 74 73 2f 69 6e 66 6f 2e 70 68 70 } //2 /infects/info.php
		$a_01_2 = {73 65 6e 68 61 3d 44 41 54 41 2e 2e 3a } //1 senha=DATA..:
		$a_01_3 = {48 4f 52 41 53 2e 2e 3a } //1 HORAS..:
		$a_01_4 = {43 6f 70 20 4c 54 44 41 2e 2e 2e } //1 Cop LTDA...
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}