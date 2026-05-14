
rule Trojan_Win64_Amadey_CCN_MTB{
	meta:
		description = "Trojan:Win64/Amadey.CCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 1f 32 03 88 45 c0 4c 89 7d c8 4c 89 7d d8 48 c7 45 e0 0f 00 00 00 c6 45 c8 00 41 b8 01 00 00 00 48 8d 55 c0 48 8d 4d c8 e8 ?? ?? 02 00 ?? 48 8d 55 c8 48 83 7d e0 10 48 0f 43 55 c8 4c 8b 45 d8 49 8b ce e8 ?? ?? 02 00 ?? 48 8b 55 e0 48 83 fa 10 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}