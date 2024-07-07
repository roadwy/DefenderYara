
rule Trojan_Win64_Qakbot_PQ_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.PQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 8b 04 01 49 83 c1 04 8b 43 90 01 01 44 0f af 43 90 01 01 83 e8 90 01 01 09 43 90 01 01 8b 93 90 02 04 8b 4b 90 01 01 8d 82 90 02 04 03 c1 31 43 90 01 01 8d 41 90 02 04 0b c2 89 83 90 02 04 48 63 8b 90 02 04 48 8b 83 90 02 04 44 88 04 01 ff 83 90 02 04 8b 4b 90 01 01 33 8b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}