
rule Ransom_Win32_ContiCrypt_PD_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 56 57 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 01 02 c6 45 90 00 } //1
		$a_03_1 = {0f b6 c0 2b c8 8b c1 c1 e0 90 01 01 2b c1 03 c0 99 f7 ff 8d 42 90 01 01 99 f7 ff 88 54 35 90 01 01 46 83 fe 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}