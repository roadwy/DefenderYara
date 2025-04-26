
rule Trojan_Win64_Latrodectus_QEZ_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.QEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 48 74 33 48 0c 41 8b 42 40 83 f1 01 0f af c1 41 8b d0 c1 ea 08 41 89 42 40 48 8b 05 43 e5 00 00 48 63 88 ?? ?? ?? ?? 49 8b 82 e8 00 00 00 88 14 01 48 8b 05 2b e5 00 00 ff 80 ?? ?? ?? ?? 49 63 8a ?? ?? ?? ?? 49 8b 82 e8 00 00 00 44 88 04 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}