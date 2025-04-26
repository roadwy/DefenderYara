
rule Ransom_Win32_Chaos_CCJU_MTB{
	meta:
		description = "Ransom:Win32/Chaos.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 04 32 33 d2 88 46 01 8b 44 24 24 03 c6 f7 74 24 10 0f b6 82 ?? ?? ?? ?? 8b 54 24 28 32 04 32 88 46 02 83 c6 05 8d 04 37 } //2
		$a_01_1 = {2e 00 63 00 68 00 61 00 6f 00 73 00 } //1 .chaos
		$a_01_2 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 5f 00 73 00 74 00 65 00 70 00 } //1 encrypt_step
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}