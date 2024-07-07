
rule Trojan_Win32_RecordBreaker_RC_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 41 85 f4 41 53 44 31 04 24 41 5b f9 4d 63 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}