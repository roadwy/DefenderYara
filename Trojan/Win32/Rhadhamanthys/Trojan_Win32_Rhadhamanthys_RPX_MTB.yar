
rule Trojan_Win32_Rhadhamanthys_RPX_MTB{
	meta:
		description = "Trojan:Win32/Rhadhamanthys.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8a 1c 3e 8b c6 f7 74 24 18 8a 82 90 01 04 32 c3 02 c3 88 04 3e 0f b6 c0 50 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}