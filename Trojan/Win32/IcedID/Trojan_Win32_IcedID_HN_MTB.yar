
rule Trojan_Win32_IcedID_HN_MTB{
	meta:
		description = "Trojan:Win32/IcedID.HN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ce 83 e6 ?? 75 ?? bb ?? ?? ?? ?? 89 fb 66 01 da f6 da 6b d2 ?? c1 ca ?? 66 81 c7 ?? ?? 89 d7 30 10 40 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}