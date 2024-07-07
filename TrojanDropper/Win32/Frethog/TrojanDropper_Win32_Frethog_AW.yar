
rule TrojanDropper_Win32_Frethog_AW{
	meta:
		description = "TrojanDropper:Win32/Frethog.AW,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7a 68 65 6e 67 74 75 2e 64 61 74 } //1 zhengtu.dat
		$a_01_1 = {25 73 5c 44 4c 4c 43 61 63 68 65 5c 6c 6c 6b 25 64 2e 64 6c 6c } //1 %s\DLLCache\llk%d.dll
		$a_01_2 = {5c 44 4c 4c 43 61 63 68 65 5c 6b 73 75 73 65 72 2e 64 6c 6c } //1 \DLLCache\ksuser.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}