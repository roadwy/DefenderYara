
rule Ransom_Win32_Virlock_B{
	meta:
		description = "Ransom:Win32/Virlock.B,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {e9 00 00 00 00 81 ec 90 01 04 be 90 01 04 bf 90 00 } //5
		$a_03_1 = {e9 00 00 00 00 89 07 8b f8 8b df 90 90 b9 90 01 04 ba 90 01 04 e9 90 01 04 c3 90 00 } //5
		$a_03_2 = {e9 00 00 00 00 0f 85 90 01 04 ff d3 81 c4 90 01 04 e9 90 01 04 8a 06 32 c2 88 07 90 90 42 90 90 46 47 90 90 49 90 90 83 f9 00 e9 90 01 02 ff ff cc cc 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=15
 
}