
rule Trojan_Win32_Predator_MS_MTB{
	meta:
		description = "Trojan:Win32/Predator.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 02 5f 5d c3 90 0a 65 00 8b 02 a3 90 01 04 8b 0d 90 01 04 83 e9 90 01 01 89 0d 90 01 04 8b 0d 90 01 04 83 c1 90 02 19 c7 05 90 01 08 a1 90 01 04 01 05 90 02 08 8b 15 90 01 04 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}