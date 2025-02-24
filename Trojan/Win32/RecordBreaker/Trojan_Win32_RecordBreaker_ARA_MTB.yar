
rule Trojan_Win32_RecordBreaker_ARA_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4f 08 8a 44 32 18 88 04 0a 42 3b 57 04 72 f0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}