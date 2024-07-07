
rule TrojanDropper_Win32_Alureon_T{
	meta:
		description = "TrojanDropper:Win32/Alureon.T,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3b 21 40 49 6e 73 74 61 6c 6c 40 21 55 54 46 2d 38 21 0d 0a 54 69 74 6c 65 3d 22 43 72 61 63 6b 20 61 6e 64 20 53 65 72 69 61 6c 22 0d 0a 42 65 67 69 6e 50 72 6f 6d 70 74 3d 22 44 69 73 61 62 6c 65 20 61 6e 74 69 76 69 72 75 73 65 73 20 62 65 66 6f 72 65 20 70 61 74 63 68 69 6e 67 21 5c 6e 43 6f 6e 74 69 6e 75 65 3f 22 0d 0a 52 75 6e 50 72 6f 67 72 61 6d 3d 22 73 65 74 75 70 2e 62 61 74 22 0d 0a 3b 21 40 49 6e 73 74 61 6c 6c 45 6e 64 40 21 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}