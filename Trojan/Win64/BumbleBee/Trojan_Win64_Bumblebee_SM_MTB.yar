
rule Trojan_Win64_Bumblebee_SM_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 08 55 56 57 41 54 41 55 41 56 41 57 48 8d 6c 24 d9 48 81 ec b0 00 00 00 ff 15 ?? ?? ?? ?? bb ?? ?? ?? ?? 33 d2 48 8b c8 44 8b c3 ff 15 ?? ?? ?? ?? 44 8b c3 33 d2 48 8b c8 48 89 05 ?? ?? ?? ?? e8 } //1
		$a_00_1 = {55 64 49 50 61 78 39 48 } //1 UdIPax9H
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}