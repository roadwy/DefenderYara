
rule Trojan_Win32_Hancitor_MTB{
	meta:
		description = "Trojan:Win32/Hancitor!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff d0 0f 81 90 0a 50 00 6a 40 eb 90 02 30 8b 00 eb 90 0a ff 00 b9 00 00 00 00 eb 90 02 50 b8 90 01 04 71 90 02 50 30 07 e9 90 02 a0 47 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}