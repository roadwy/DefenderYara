
rule Virus_Win32_Expiro_NDP_MTB{
	meta:
		description = "Virus:Win32/Expiro.NDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {57 e8 00 00 00 00 ?? 81 ?? 0c ?? 08 00 ?? 00 00 00 00 } //1
		$a_03_1 = {00 04 00 00 81 ?? 00 04 00 00 81 ?? 00 c0 08 00 } //1
		$a_03_2 = {2e 72 65 6c 6f 63 00 00 00 [0-15] 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}