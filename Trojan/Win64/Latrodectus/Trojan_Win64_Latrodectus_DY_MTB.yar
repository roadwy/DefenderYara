
rule Trojan_Win64_Latrodectus_DY_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea 04 48 6b c2 13 48 2b c8 48 2b cb 8a 44 0c 20 43 32 04 ?? 41 88 02 4d 03 d4 45 3b cd 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}