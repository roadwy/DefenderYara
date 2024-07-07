
rule Trojan_Win32_Lumma_RDA_MTB{
	meta:
		description = "Trojan:Win32/Lumma.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 31 d2 f7 f6 0f b6 44 0d 00 32 04 17 88 44 0d 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}