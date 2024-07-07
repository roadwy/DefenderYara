
rule TrojanDropper_Win32_Tramox_A{
	meta:
		description = "TrojanDropper:Win32/Tramox.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 43 4f 50 49 41 52 57 4f 52 4d } //1 :COPIARWORM
		$a_01_1 = {22 4a 3a 5c 73 79 73 74 65 6d 5c 25 6a 75 65 67 6f 25 22 } //1 "J:\system\%juego%"
		$a_01_2 = {22 49 3a 5c 25 6d 6f 78 69 74 61 25 22 } //1 "I:\%moxita%"
		$a_01_3 = {22 45 3a 5c 25 74 72 61 62 61 6a 6f 25 22 } //1 "E:\%trabajo%"
		$a_01_4 = {5c 52 75 6e 20 2f 76 20 77 75 61 63 6c 74 2e 65 78 65 20 2f 74 } //1 \Run /v wuaclt.exe /t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}