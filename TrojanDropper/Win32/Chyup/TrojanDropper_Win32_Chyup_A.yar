
rule TrojanDropper_Win32_Chyup_A{
	meta:
		description = "TrojanDropper:Win32/Chyup.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 50 43 20 31 2e 30 2e 36 20 5b 32 30 30 32 2f 30 34 2f 32 33 5d 20 66 6f 72 20 69 33 38 36 20 2d 20 57 49 4e 33 32 } //1 FPC 1.0.6 [2002/04/23] for i386 - WIN32
		$a_01_1 = {4b 2d 4d 65 6c 65 6f 6e 5c 00 0c 00 00 00 0c 00 00 00 ff ff ff ff 46 69 6e 65 42 72 6f 77 73 65 72 5c 00 09 } //1
		$a_01_2 = {53 45 41 47 55 4c 4c 5c 46 54 50 5c 00 0d 00 00 00 0d 00 00 00 ff ff ff ff 41 63 6f 6f 20 42 72 6f 77 73 65 72 5c 00 07 } //1
		$a_01_3 = {68 6e 65 74 63 66 67 2e 64 6c 6c 00 0c 00 00 00 0c 00 00 00 ff ff ff ff 72 61 73 61 64 68 6c 70 2e 64 6c 6c 00 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}