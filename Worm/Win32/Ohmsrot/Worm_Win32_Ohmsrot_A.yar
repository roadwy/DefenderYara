
rule Worm_Win32_Ohmsrot_A{
	meta:
		description = "Worm:Win32/Ohmsrot.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 4e 54 49 48 4f 53 54 2e 45 58 45 00 } //1
		$a_01_1 = {53 53 56 49 43 48 4f 53 53 54 2e 45 58 45 00 } //1
		$a_01_2 = {3a 5c 4e 6f 48 6f 73 74 2e 65 78 65 00 } //1
		$a_01_3 = {52 75 6e 00 00 00 ff ff ff ff 07 00 00 00 6e 6f 68 6f 73 73 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}