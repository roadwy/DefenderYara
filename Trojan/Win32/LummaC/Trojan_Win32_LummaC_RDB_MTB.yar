
rule Trojan_Win32_LummaC_RDB_MTB{
	meta:
		description = "Trojan:Win32/LummaC.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 28 8b 5c 24 34 8b 54 24 40 59 8b 4c b5 00 8a 04 33 6a 03 30 04 11 b9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}