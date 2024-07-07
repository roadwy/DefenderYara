
rule Trojan_Win32_Azorult_GS_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 74 24 14 90 05 10 01 90 5f 50 58 ff 74 24 18 90 05 10 01 90 5e 89 c0 8a 2f 90 05 10 01 90 8a 0e 50 88 e8 30 c8 88 07 58 ff 44 24 0c 8b 5c 24 0c 3b 5c 24 08 7e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}