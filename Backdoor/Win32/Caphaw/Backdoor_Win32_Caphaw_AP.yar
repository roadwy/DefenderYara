
rule Backdoor_Win32_Caphaw_AP{
	meta:
		description = "Backdoor:Win32/Caphaw.AP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 75 1c ff 75 18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 15 90 01 04 8b f0 90 00 } //3
		$a_01_1 = {0f b6 71 0d 33 de 0f b6 71 0e 0f b6 49 0f c1 e3 08 33 de c1 e3 08 33 d9 33 dd 8b cb c1 e9 10 0f b6 c9 8b 0c 8d } //3
		$a_01_2 = {51 2b d3 50 03 d0 ff d2 } //1
		$a_01_3 = {52 2b c3 55 03 c5 ff d0 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}