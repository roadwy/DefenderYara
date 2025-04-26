
rule Trojan_Win32_BlackWidow_GVE_MTB{
	meta:
		description = "Trojan:Win32/BlackWidow.GVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 f9 07 38 05 00 90 13 [0-5f] 31 d2 [0-5f] f7 f3 [0-5f] 8a 04 16 [0-5f] 30 04 0f [0-5f] 41 [0-5f] 89 c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}