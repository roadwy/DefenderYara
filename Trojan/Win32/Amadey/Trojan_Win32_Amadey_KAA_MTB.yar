
rule Trojan_Win32_Amadey_KAA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a ca 2a c8 80 c1 ?? 30 ?? 15 [0-04] 42 89 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}