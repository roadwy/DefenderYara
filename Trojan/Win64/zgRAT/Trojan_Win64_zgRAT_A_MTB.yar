
rule Trojan_Win64_ZgRAT_A_MTB{
	meta:
		description = "Trojan:Win64/ZgRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 00 83 f8 ff 74 ?? a8 10 75 ?? 48 8d 0d ?? ?? ?? 00 ff 15 ?? ?? 02 00 83 f8 ff 74 ?? a8 10 75 ?? 48 8d 0d ?? ?? ?? 00 ff 15 ?? ?? 02 00 83 f8 ff 0f 84 ?? ?? 00 00 a8 10 0f 84 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}