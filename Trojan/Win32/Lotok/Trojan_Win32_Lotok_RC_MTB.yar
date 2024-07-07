
rule Trojan_Win32_Lotok_RC_MTB{
	meta:
		description = "Trojan:Win32/Lotok.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 44 24 2c 2a c3 03 d1 8b 0d 90 01 04 32 c3 89 15 90 01 04 8b 54 24 1c 2b cd 02 c3 89 0d 90 01 04 88 04 17 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}