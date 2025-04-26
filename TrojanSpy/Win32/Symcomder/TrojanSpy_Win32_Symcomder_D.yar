
rule TrojanSpy_Win32_Symcomder_D{
	meta:
		description = "TrojanSpy:Win32/Symcomder.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 44 65 6c 61 79 00 4b 65 79 62 6f 61 72 64 53 70 65 65 64 00 } //1
		$a_01_1 = {7b 43 6c 69 6b 7d 0d 0a 00 7b 42 61 63 6b 7d } //1
		$a_01_2 = {7b 43 4c 49 50 42 4f 41 52 44 20 45 4e 44 7d } //1 {CLIPBOARD END}
		$a_03_3 = {75 6e 5d 20 3e 3e 20 25 54 45 4d 50 25 5c [0-0a] 2e 72 65 67 0d 0a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}