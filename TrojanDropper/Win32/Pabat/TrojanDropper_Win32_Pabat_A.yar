
rule TrojanDropper_Win32_Pabat_A{
	meta:
		description = "TrojanDropper:Win32/Pabat.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 22 43 3a 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 62 6f 6f 74 63 66 67 2e 65 78 65 22 20 2f 46 20 2f 53 20 2f 51 0d 0a 6d 73 67 20 2a 20 4c 4f 4c } //1
		$a_01_1 = {6d 73 67 20 2a 20 4c 4f 4c 0d 0a 73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 31 30 30 20 2d 63 20 22 56 49 52 55 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}