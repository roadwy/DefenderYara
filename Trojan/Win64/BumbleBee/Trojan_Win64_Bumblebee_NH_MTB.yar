
rule Trojan_Win64_Bumblebee_NH_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 63 c5 48 98 32 14 30 48 8b 05 ?? ?? ?? ?? 0f b6 4c 06 ?? 0f b6 c2 33 d2 0f af c1 0f b6 cb 41 ?? ?? 02 c3 43 ?? ?? ?? 0f b6 07 48 ?? ?? 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}