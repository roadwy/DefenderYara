
rule Trojan_Win64_BruteRatel_UL_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.UL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8d 52 01 44 0f b6 d2 0f b6 d2 0f b6 04 14 42 8d 0c 08 44 0f b6 c9 0f b6 c9 0f b6 3c 0c 40 88 3c 14 88 04 0c 02 04 14 0f b6 c0 0f b6 04 04 42 32 04 03 42 88 04 06 4c 89 c0 49 83 c0 01 49 39 c3 75 bd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}