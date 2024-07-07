
rule Trojan_Win32_ExpInject_VC_MTB{
	meta:
		description = "Trojan:Win32/ExpInject.VC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 30 88 15 90 01 04 8b 15 90 01 04 8a 04 30 8a 1c 11 32 d8 88 1c 11 a1 90 01 04 40 83 f8 90 01 01 a3 90 01 04 90 13 8b 0d 90 01 04 c7 05 90 01 08 41 4f 89 0d 90 01 04 90 13 8b 35 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}