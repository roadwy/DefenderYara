
rule Trojan_Win32_DarkGate_BKC_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.BKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 f9 8b 44 24 04 8a 04 10 8b 14 24 8b 0d a0 f8 5e 00 8a 54 0a ff 32 c2 50 8b 44 24 0c e8 32 e8 f8 ff 8b 15 a0 f8 5e 00 59 88 4c 10 ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}