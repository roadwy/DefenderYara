
rule TrojanDropper_Win32_Machime_A{
	meta:
		description = "TrojanDropper:Win32/Machime.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 6d 69 6d 61 63 68 69 6e 65 32 2e 64 6c 6c 00 45 58 45 00 5c 69 6d 65 5c 00 00 00 2e 4e 45 54 20 52 75 6e 74 69 6d 65 20 4f 70 74 69 6d 69 7a 61 74 69 6f 6e 20 53 65 72 76 69 63 65 20 76 32 2e 30 38 36 35 32 31 2e 42 61 63 6b 55 70 5f 58 38 36 } //1
		$a_01_1 = {3a 73 74 61 72 74 0d 0a 64 65 6c 20 22 25 73 22 0d 0a 69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 73 74 61 72 74 0d 0a 64 65 6c 20 25 25 30 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}