
rule BrowserModifier_Win32_Kerlofost{
	meta:
		description = "BrowserModifier:Win32/Kerlofost,SIGNATURE_TYPE_PEHSTR,19 00 19 00 06 00 00 "
		
	strings :
		$a_01_0 = {42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //10 Browser Helper Objects
		$a_01_1 = {2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //10 䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_2 = {72 65 6b 6c 6f 73 6f 66 74 2e 72 75 } //2 reklosoft.ru
		$a_01_3 = {72 65 6b 6c 6f 73 6f 66 74 5f 61 64 77 2e } //2 reklosoft_adw.
		$a_01_4 = {46 46 46 46 45 37 30 38 2d 42 38 33 32 2d 34 32 46 31 2d 42 41 46 46 2d 32 34 37 37 35 33 42 35 45 34 35 32 } //1 FFFFE708-B832-42F1-BAFF-247753B5E452
		$a_01_5 = {37 31 45 35 39 44 33 37 2d 44 37 46 43 2d 34 45 44 36 2d 42 43 31 44 2d 44 31 33 42 45 30 32 46 45 36 43 35 } //1 71E59D37-D7FC-4ED6-BC1D-D13BE02FE6C5
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=25
 
}