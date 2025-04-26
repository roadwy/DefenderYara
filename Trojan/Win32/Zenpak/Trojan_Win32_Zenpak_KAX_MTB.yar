
rule Trojan_Win32_Zenpak_KAX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 56 8a 45 [0-32] 30 c8 81 c2 [0-0f] 0f b6 c0 5e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}