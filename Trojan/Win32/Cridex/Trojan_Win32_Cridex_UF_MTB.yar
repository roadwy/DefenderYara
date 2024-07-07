
rule Trojan_Win32_Cridex_UF_MTB{
	meta:
		description = "Trojan:Win32/Cridex.UF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 44 08 b0 90 01 02 8d 9c 59 90 01 04 bd 90 01 04 2b e9 2b ee 83 c1 01 03 c5 0f af c8 81 c2 90 01 04 89 17 83 c7 04 83 6c 24 10 01 8d 8c 90 01 05 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}