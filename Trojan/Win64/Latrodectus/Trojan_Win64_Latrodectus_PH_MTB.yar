
rule Trojan_Win64_Latrodectus_PH_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 ca 48 b8 cd cc cc cc cc cc cc cc 44 03 d6 48 f7 e1 48 c1 ea 04 48 8d ?? 92 48 c1 e0 ?? 48 2b c8 8a 44 0c ?? 43 32 04 0b 41 88 01 4c 03 ce 45 3b d7 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}