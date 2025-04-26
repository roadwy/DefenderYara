
rule Trojan_Win64_StealBit_SC{
	meta:
		description = "Trojan:Win64/StealBit.SC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c9 8b c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 83 f9 7c 72 e9 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}