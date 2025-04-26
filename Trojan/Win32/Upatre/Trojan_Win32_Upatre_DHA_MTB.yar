
rule Trojan_Win32_Upatre_DHA_MTB{
	meta:
		description = "Trojan:Win32/Upatre.DHA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 02 8b 06 83 c6 04 bb 08 08 08 08 31 d8 89 07 83 c7 04 83 e9 01 83 f9 00 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}