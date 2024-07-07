
rule Trojan_Win64_Dridex_PV_MTB{
	meta:
		description = "Trojan:Win64/Dridex.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 24 47 24 90 01 01 88 90 02 06 8b 90 02 06 48 8b 90 02 03 48 83 90 02 02 48 89 90 02 06 81 90 02 05 48 8b 90 02 08 2a 90 02 03 48 8b 90 02 03 4c 8b 90 02 03 41 88 90 02 02 03 90 02 06 89 90 02 06 8a 90 02 05 88 90 02 06 44 8b 90 02 05 c9 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}