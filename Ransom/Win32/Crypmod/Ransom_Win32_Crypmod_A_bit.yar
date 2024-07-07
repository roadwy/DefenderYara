
rule Ransom_Win32_Crypmod_A_bit{
	meta:
		description = "Ransom:Win32/Crypmod.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c6 0f b6 c9 2b c1 8b 0d 90 01 04 2b 0d 90 01 04 41 3b c1 7f 07 8b c6 a3 90 00 } //1
		$a_03_1 = {88 04 0a 0f b7 0d 90 01 04 03 0d 90 01 04 42 3b 55 90 01 01 0f 8c 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}