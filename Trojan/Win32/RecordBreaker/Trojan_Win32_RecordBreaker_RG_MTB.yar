
rule Trojan_Win32_RecordBreaker_RG_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 67 66 66 66 89 c8 f7 ea c1 fa 02 89 c8 c1 f8 1f 29 c2 89 d0 05 96 00 00 00 29 85 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}