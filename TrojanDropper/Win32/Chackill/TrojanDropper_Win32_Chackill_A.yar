
rule TrojanDropper_Win32_Chackill_A{
	meta:
		description = "TrojanDropper:Win32/Chackill.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 66 75 63 6b 33 36 30 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_2 = {2e 32 35 36 63 68 61 2e 63 6e } //01 00  .256cha.cn
		$a_01_3 = {2e 70 68 70 3f 74 6e 3d } //00 00  .php?tn=
	condition:
		any of ($a_*)
 
}