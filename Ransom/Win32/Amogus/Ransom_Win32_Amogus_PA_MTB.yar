
rule Ransom_Win32_Amogus_PA_MTB{
	meta:
		description = "Ransom:Win32/Amogus.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 61 6d 6f 67 75 73 } //1 .amogus
		$a_03_1 = {0f b6 56 01 83 c7 10 83 c6 10 32 53 01 88 57 ?? 8b 4c 24 ?? 0f b6 56 ?? 32 53 02 88 51 02 8b 4c 24 ?? 0f b6 56 ?? 32 53 03 88 51 03 8b 54 24 ?? 0f b6 4e ?? 32 4b 04 88 4a 04 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}