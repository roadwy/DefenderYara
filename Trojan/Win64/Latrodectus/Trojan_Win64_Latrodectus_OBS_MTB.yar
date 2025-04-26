
rule Trojan_Win64_Latrodectus_OBS_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.OBS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {49 63 ca 48 b8 ab aa aa aa aa aa aa aa 41 ff c2 48 f7 e1 48 c1 ea 04 48 8d 04 52 48 c1 e0 03 48 2b c8 49 03 cb 8a 44 0c 20 42 32 04 0b 41 88 01 49 ff c1 45 3b d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}