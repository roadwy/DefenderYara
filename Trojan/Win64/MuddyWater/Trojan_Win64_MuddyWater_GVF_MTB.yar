
rule Trojan_Win64_MuddyWater_GVF_MTB{
	meta:
		description = "Trojan:Win64/MuddyWater.GVF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 f9 13 77 26 0f b6 54 31 02 c1 e2 10 44 0f b7 04 31 44 01 c2 81 c2 00 00 00 f0 33 14 08 89 94 0c 80 01 00 00 48 83 c1 04 eb d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}