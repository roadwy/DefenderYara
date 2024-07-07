
rule PWS_Win32_Lolyda_AY{
	meta:
		description = "PWS:Win32/Lolyda.AY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e6 19 c1 e8 07 0b f0 0f be c1 8a 4a 01 03 c6 42 84 c9 75 e9 } //1
		$a_00_1 = {6d 69 62 61 6f 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 70 75 74 26 75 3d 25 73 } //1 mibao.php?action=put&u=%s
		$a_01_2 = {3f 73 3d 25 73 26 75 3d 25 73 26 } //1 ?s=%s&u=%s&
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}