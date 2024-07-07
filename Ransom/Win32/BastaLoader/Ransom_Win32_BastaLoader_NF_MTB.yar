
rule Ransom_Win32_BastaLoader_NF_MTB{
	meta:
		description = "Ransom:Win32/BastaLoader.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 01 33 c0 8b 15 90 01 04 40 2b 05 90 01 04 42 2b 05 90 01 04 01 05 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 a1 90 01 04 31 0d 90 01 04 89 15 90 01 04 89 0d 90 01 04 88 1c 02 ff 05 90 01 04 81 fe 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}