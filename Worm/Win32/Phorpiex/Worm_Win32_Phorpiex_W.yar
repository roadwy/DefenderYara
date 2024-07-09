
rule Worm_Win32_Phorpiex_W{
	meta:
		description = "Worm:Win32/Phorpiex.W,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 25 73 5c 25 73 25 69 25 69 2e 65 78 65 00 } //1
		$a_03_1 = {5b 44 6f 77 6e 6c 6f 61 64 5d 3a [0-10] 5b 4d 61 69 6e 5d 3a } //1
		$a_03_2 = {81 39 50 45 00 00 0f 85 ?? ?? ?? ?? 8b 7d 0c 8b 81 a0 00 00 00 2b 79 34 8b 91 a4 00 00 00 03 c6 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*10) >=11
 
}