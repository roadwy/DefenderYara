
rule Trojan_Win32_Nymeria_ARA_MTB{
	meta:
		description = "Trojan:Win32/Nymeria.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {71 6a 77 72 6b 72 64 63 74 2e 70 64 66 } //qjwrkrdct.pdf  2
		$a_80_1 = {71 6c 69 6e 68 6d 2e 78 6c } //qlinhm.xl  2
		$a_01_2 = {54 65 6d 70 4d 6f 64 65 } //2 TempMode
		$a_01_3 = {73 69 6c 65 6e 74 3d 31 74 45 32 35 47 41 32 43 33 4f 6e 77 6b 32 31 } //2 silent=1tE25GA2C3Onwk21
		$a_01_4 = {53 65 74 75 70 3d 69 6a 68 2d 64 2e 76 62 65 } //2 Setup=ijh-d.vbe
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}