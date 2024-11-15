
rule Trojan_Win32_Menti_GNE_MTB{
	meta:
		description = "Trojan:Win32/Menti.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {1b e6 ec 37 e6 5e 30 10 } //5
		$a_03_1 = {44 00 34 00 32 00 37 00 46 ?? 38 00 32 00 44 } //5
		$a_80_2 = {66 69 6c 65 2e 74 6b 79 } //file.tky  1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}