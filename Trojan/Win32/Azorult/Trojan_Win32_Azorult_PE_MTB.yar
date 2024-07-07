
rule Trojan_Win32_Azorult_PE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c3 fc 3b 5c 24 10 7c 54 8b 5c 24 90 01 01 03 5c 24 10 89 5c 24 14 8b 5c 24 04 03 5c 24 0c 89 5c 24 18 ff 74 24 14 90 90 90 05 0a 01 90 5f 50 58 ff 74 24 18 90 90 90 05 0a 01 90 5e 89 c0 8a 2f 90 90 90 05 0a 01 90 8a 0e 50 88 e8 30 c8 88 07 58 ff 44 24 0c 8b 5c 24 0c 3b 5c 24 08 7e 08 c7 44 24 0c 00 00 00 00 83 44 24 10 04 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}