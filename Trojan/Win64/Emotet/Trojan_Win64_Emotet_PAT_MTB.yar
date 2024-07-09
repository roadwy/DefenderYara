
rule Trojan_Win64_Emotet_PAT_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b ce 2b c8 48 63 c1 8a 4c 04 ?? 48 8b 05 [0-04] 44 8a 14 02 ba [0-04] 8b 05 ?? ?? ?? ?? 44 32 d1 0f af [0-06] 2b d0 [0-a0] 48 63 c8 44 88 14 19 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}