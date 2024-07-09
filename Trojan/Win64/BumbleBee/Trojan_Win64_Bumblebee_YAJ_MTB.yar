
rule Trojan_Win64_Bumblebee_YAJ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.YAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 83 ac 00 00 00 48 8b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 41 8b d0 2b 48 6c 81 e9 ?? ?? ?? ?? c1 ea 08 31 8b 40 01 00 00 48 8b 05 da 55 11 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}