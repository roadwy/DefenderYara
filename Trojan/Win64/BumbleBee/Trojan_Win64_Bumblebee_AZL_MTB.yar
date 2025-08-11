
rule Trojan_Win64_Bumblebee_AZL_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AZL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 0f b6 8c 24 69 9a 01 00 2b c1 48 8b 8c 24 f0 01 00 00 88 01 e8 ?? ?? ?? ?? 48 8b 80 f8 0f 00 00 48 8b 8c 24 98 ca 00 00 48 89 4c 24 20 45 33 c9 45 33 c0 ba 02 00 00 00 48 8b 8c 24 ?? 60 01 00 ff 50 48 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}