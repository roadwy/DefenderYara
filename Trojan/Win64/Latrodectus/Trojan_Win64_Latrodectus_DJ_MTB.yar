
rule Trojan_Win64_Latrodectus_DJ_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 cb 49 8b c1 ff c3 4d 8d 40 01 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 48 8b 45 0f 0f b6 4c 0d 27 43 32 4c 10 ff 41 88 4c 00 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}