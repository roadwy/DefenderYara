
rule Worm_Win32_Crastic_gen_A{
	meta:
		description = "Worm:Win32/Crastic.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {30 18 8a 0c 39 32 08 48 88 48 01 fe ca 4e 75 e6 32 d2 b8 } //1
		$a_01_1 = {7f 11 7c 08 81 ff a0 86 01 00 73 07 bf } //1
		$a_01_2 = {83 bd e8 fe ff ff 10 8b cf 73 06 8d 8d d4 fe ff ff 80 3c 01 5c 75 0a 42 83 fa 01 0f 87 } //1
		$a_03_3 = {6a 27 53 ff 15 ?? ?? ?? ?? 3b c3 75 2c 8d 85 ?? ?? ?? ?? 8d 50 01 8a 08 40 3a cb 75 f9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}