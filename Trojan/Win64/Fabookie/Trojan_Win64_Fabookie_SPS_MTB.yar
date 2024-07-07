
rule Trojan_Win64_Fabookie_SPS_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.SPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 45 e0 41 b9 16 00 00 00 48 2b c8 4c 8d 45 e0 4e 8d 1c 11 43 8a 0c 03 41 ff c9 41 8a 00 49 ff c0 3a c8 75 0d 45 85 c9 75 ea 48 63 c2 49 03 c2 eb 12 ff c2 48 63 ca 48 81 f9 00 e0 0e 00 72 bf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}