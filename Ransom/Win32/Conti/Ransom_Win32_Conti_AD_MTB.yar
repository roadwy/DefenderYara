
rule Ransom_Win32_Conti_AD_MTB{
	meta:
		description = "Ransom:Win32/Conti.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {80 39 00 75 ?? 53 56 57 bf ?? 00 00 00 8d 71 01 8d 5f ?? 8a 06 8d 76 01 0f b6 c0 83 e8 } //1
		$a_03_1 = {99 f7 fb 8d 42 ?? 99 f7 fb 88 56 ff 83 ef 01 75 ?? 5f 5e 5b 8d 41 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}