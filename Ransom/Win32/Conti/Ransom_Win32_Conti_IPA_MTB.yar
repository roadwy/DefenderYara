
rule Ransom_Win32_Conti_IPA_MTB{
	meta:
		description = "Ransom:Win32/Conti.IPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 2b c8 6b c1 ?? 99 f7 ff 8d 42 7f 99 f7 ff 88 94 35 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}