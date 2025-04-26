
rule Trojan_Win64_Qakbot_PQ_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8b 04 01 49 83 c1 04 8b 43 ?? 44 0f af 43 ?? 83 e8 ?? 09 43 ?? 8b 93 [0-04] 8b 4b ?? 8d 82 [0-04] 03 c1 31 43 ?? 8d 41 [0-04] 0b c2 89 83 [0-04] 48 63 8b [0-04] 48 8b 83 [0-04] 44 88 04 01 ff 83 [0-04] 8b 4b ?? 33 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}