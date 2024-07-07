
rule Trojan_Win32_Emotet_PDZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 2c 90 01 01 03 c1 99 b9 90 01 04 f7 f9 8b 4c 24 90 01 01 8b b4 24 90 01 04 8a 04 31 8a 54 14 90 01 01 32 c2 88 04 31 90 00 } //1
		$a_81_1 = {34 33 49 32 73 31 55 66 45 78 39 49 69 68 70 4f 70 32 35 72 54 4f 44 61 42 52 6b 64 54 75 7e 72 51 7a 4e 4a 41 47 6c 35 56 } //1 43I2s1UfEx9IihpOp25rTODaBRkdTu~rQzNJAGl5V
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}