
rule Worm_Win32_Enosch_A{
	meta:
		description = "Worm:Win32/Enosch.A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 65 63 74 75 72 65 20 6e 6f 74 65 73 2e 65 78 65 00 00 00 65 73 73 61 79 2e 65 78 65 00 } //10
		$a_01_1 = {65 6e 6f 75 67 68 73 63 68 6f 6f 6c 40 67 6d 61 69 6c 2e 63 6f 6d 00 } //1
		$a_01_2 = {6d 61 6d 61 6d 6d 6d 61 6d 61 6d 61 6d 40 79 61 68 6f 6f 2e 63 6f 6d 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}