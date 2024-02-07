
rule PWS_Win32_Frethog_MT{
	meta:
		description = "PWS:Win32/Frethog.MT,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 07 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {54 46 75 63 6b 4e 4f 44 } //02 00  TFuckNOD
		$a_01_1 = {4d 69 6e 69 53 6e 69 66 66 65 72 43 6c 61 73 73 } //02 00  MiniSnifferClass
		$a_01_2 = {55 6e 69 74 5f 5a 54 46 75 6e } //03 00  Unit_ZTFun
		$a_01_3 = {4b 4e 54 4d 53 50 2d 4c 4c 4b 33 34 5a 31 54 41 42 44 } //01 00  KNTMSP-LLK34Z1TABD
		$a_01_4 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c } //00 00  MAIL FROM: <
	condition:
		any of ($a_*)
 
}