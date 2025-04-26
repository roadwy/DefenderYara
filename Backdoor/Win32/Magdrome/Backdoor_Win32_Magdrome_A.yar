
rule Backdoor_Win32_Magdrome_A{
	meta:
		description = "Backdoor:Win32/Magdrome.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d3 c1 e2 10 0b ca 8b 54 24 2c 89 0c aa 8b f7 83 c5 01 8b c8 2b f0 8d 9b 00 00 00 00 } //1
		$a_01_1 = {44 52 49 56 45 52 3d 7b 53 51 4c 20 53 65 72 76 65 72 7d 3b 53 45 52 56 45 52 3d 25 73 2c 25 64 3b 55 49 44 3d 25 73 3b 50 57 44 3d 25 73 } //1 DRIVER={SQL Server};SERVER=%s,%d;UID=%s;PWD=%s
		$a_01_2 = {5f 67 75 61 6d 61 5f } //1 _guama_
		$a_01_3 = {37 34 2e 38 32 2e 31 36 36 2e 31 31 35 } //1 74.82.166.115
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}