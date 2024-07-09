
rule Virus_Win32_Phdet_A{
	meta:
		description = "Virus:Win32/Phdet.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {b9 24 06 00 00 89 4e 1c 81 fa 04 c0 22 00 74 27 bf 10 00 00 c0 } //1
		$a_01_1 = {68 a3 6d 42 2a } //1
		$a_03_2 = {3d b1 1d 00 00 0f 8f ?? ?? ?? ?? 3d b0 1d 00 00 0f 8d ?? ?? ?? ?? 3d 28 0a 00 00 0f 84 ?? ?? ?? ?? 3d ce 0e 00 00 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}