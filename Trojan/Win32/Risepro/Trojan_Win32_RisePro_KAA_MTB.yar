
rule Trojan_Win32_RisePro_KAA_MTB{
	meta:
		description = "Trojan:Win32/RisePro.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 15 90 01 04 32 c8 8b 3d 90 01 04 88 4d dc 3b d7 73 21 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}