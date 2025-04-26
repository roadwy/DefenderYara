
rule PWS_Win32_Barus_A{
	meta:
		description = "PWS:Win32/Barus.A,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 89 e7 ac 88 c7 8a 27 47 c0 ec 04 28 e0 73 f6 8a 47 ff 24 0f 3c 0c 75 03 5a f7 d2 } //10
		$a_01_1 = {2d 2d 37 64 30 31 35 38 31 33 38 30 32 63 34 } //1 --7d015813802c4
		$a_01_2 = {6d 6f 6e 65 79 2e 79 61 6e 64 65 78 2e 72 75 } //1 money.yandex.ru
		$a_01_3 = {72 61 69 66 66 65 69 73 65 6e 2e 72 75 } //1 raiffeisen.ru
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}