
rule Trojan_Win32_Blister_RTQ_MTB{
	meta:
		description = "Trojan:Win32/Blister.RTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c6 83 e0 03 8a 44 05 e8 30 04 1e 46 81 fe e0 89 01 00 72 eb } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}