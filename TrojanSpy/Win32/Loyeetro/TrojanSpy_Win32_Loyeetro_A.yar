
rule TrojanSpy_Win32_Loyeetro_A{
	meta:
		description = "TrojanSpy:Win32/Loyeetro.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 4c 6f 67 20 53 74 61 72 74 65 64 5d 20 2d 20 5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 20 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d } //1 [Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]
		$a_01_1 = {7b 47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //1 {GET %s HTTP/1.1
		$a_01_2 = {25 4e 5c 25 4e 2e 55 41 55 } //1 %N\%N.UAU
		$a_01_3 = {73 74 61 72 74 20 2f 62 20 22 22 20 63 6d 64 20 2f 63 20 64 65 6c 20 22 25 25 7e 66 30 22 26 65 78 69 74 20 2f 62 } //1 start /b "" cmd /c del "%%~f0"&exit /b
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}