
rule Trojan_Win64_StrelaStealer_AB_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af d0 f6 c2 01 0f 94 44 24 36 ba 16 c9 84 07 b8 95 81 79 a6 0f 44 c2 83 f9 0a 0f 9c 44 24 37 0f 4c c2 ba } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}