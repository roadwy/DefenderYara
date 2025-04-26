
rule Ransom_Win32_Ouroboros_GG_MTB{
	meta:
		description = "Ransom:Win32/Ouroboros.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {5c 00 6d 00 6f 00 74 00 68 00 65 00 72 00 66 00 75 00 63 00 6b 00 65 00 72 00 5c 00 [0-0f] 5c 00 6d 00 6f 00 74 00 68 00 65 00 72 00 66 00 75 00 63 00 6b 00 65 00 72 00 2e 00 70 00 64 00 62 00 } //1
		$a_02_1 = {5c 6d 6f 74 68 65 72 66 75 63 6b 65 72 5c [0-0f] 5c 6d 6f 74 68 65 72 66 75 63 6b 65 72 2e 70 64 62 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}