
rule PWS_Win32_Tibia_CA{
	meta:
		description = "PWS:Win32/Tibia.CA,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 69 62 69 61 43 6c 69 65 6e 74 00 } //1 楔楢䍡楬湥t
		$a_01_1 = {26 63 68 65 63 6b 3d 00 26 70 6f 73 3d 00 } //1 挦敨正=瀦獯=
		$a_03_2 = {26 70 61 73 73 77 6f 72 64 3d 90 02 05 26 6c 6f 67 69 6e 3d 90 02 05 26 69 64 3d 90 00 } //1
		$a_01_3 = {6e 69 67 68 74 74 69 62 69 61 2e 78 61 61 2e 70 6c } //1 nighttibia.xaa.pl
		$a_01_4 = {4e 69 67 68 74 4d 41 52 45 4b 5c 4d 6f 6a 65 20 64 6f 6b 75 6d 65 6e 74 79 5c } //1 NightMAREK\Moje dokumenty\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}