
rule Trojan_Win32_Bandra_RPV_MTB{
	meta:
		description = "Trojan:Win32/Bandra.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 33 d2 8b c5 f7 f1 8b 44 24 1c 8b 4c 24 18 56 56 8a 04 02 32 04 19 88 03 ff d7 8b 5c 24 10 45 3b 6c 24 20 72 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}