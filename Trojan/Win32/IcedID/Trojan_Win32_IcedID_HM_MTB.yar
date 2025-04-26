
rule Trojan_Win32_IcedID_HM_MTB{
	meta:
		description = "Trojan:Win32/IcedID.HM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ce 83 e6 ?? 75 ?? 8b 5d ?? 66 01 da f6 da 6b d2 ?? c1 ca ?? 89 55 ?? 30 10 40 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}