
rule Trojan_Win32_Bayrob_MK_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 c8 89 45 08 8b d0 8a 45 08 c1 ea 08 02 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Bayrob_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Bayrob.MK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 11 29 d1 31 f6 8a 1c 32 88 1c 30 46 39 f1 75 f5 01 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}