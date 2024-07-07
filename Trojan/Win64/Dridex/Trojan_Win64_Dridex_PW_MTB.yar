
rule Trojan_Win64_Dridex_PW_MTB{
	meta:
		description = "Trojan:Win64/Dridex.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 f2 4c 8b 90 02 03 49 81 90 02 05 4c 89 90 02 03 4c 90 02 04 41 8a 90 02 02 28 d8 48 8b 90 02 03 48 89 90 02 03 4c 8b 90 02 03 41 88 90 02 02 66 8b 90 02 03 66 81 90 02 03 66 89 90 02 03 45 01 90 01 01 66 c7 90 02 05 44 89 90 02 03 48 29 90 01 01 48 89 90 02 03 44 8b 90 02 03 45 39 90 01 01 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}