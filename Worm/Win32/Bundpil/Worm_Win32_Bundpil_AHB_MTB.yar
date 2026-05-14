
rule Worm_Win32_Bundpil_AHB_MTB{
	meta:
		description = "Worm:Win32/Bundpil.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {2a c8 8a c1 88 0d ?? ?? 00 10 b1 ?? f6 e9 a2 ?? ?? 00 10 e8 ?? ?? ?? ?? b1 ?? 2a c8 4e 88 0d } //30
		$a_01_1 = {53 73 4d 70 4b 6e 49 6c 46 66 41 64 78 61 } //20 SsMpKnIlFfAdxa
		$a_01_2 = {61 42 55 79 53 76 50 73 4e 6e 48 6b 46 69 } //10 aBUySvPsNnHkFi
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}