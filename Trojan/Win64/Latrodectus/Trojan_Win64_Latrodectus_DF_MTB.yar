
rule Trojan_Win64_Latrodectus_DF_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 e3 48 c1 ea 04 48 ff c3 48 8d 04 d2 48 03 c0 48 2b c8 8a 44 0d ?? 43 32 04 02 41 88 00 48 81 fb ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}