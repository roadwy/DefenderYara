
rule TrojanSpy_Win32_Banker_ALG{
	meta:
		description = "TrojanSpy:Win32/Banker.ALG,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 4e 47 28 53 45 52 56 45 52 54 4f 50 49 4e 47 29 20 74 68 65 6e 06 1f 66 6c 61 67 20 3d 20 76 72 66 28 70 68 70 62 69 74 20 26 20 22 3f 61 3d 63 68 65 63 6b 22 29 06 10 69 66 20 66 6c 61 67 20 3d 20 31 20 74 68 65 6e 06 0b 6a 61 63 68 65 63 6b 20 3d 20 31 06 7f 46 46 20 3d 20 41 50 59 59 20 26 20 50 50 28 2d 32 37 39 2b 31 30 35 29 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}