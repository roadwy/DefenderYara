
rule Trojan_Win64_BumbleBee_SG_MTB{
	meta:
		description = "Trojan:Win64/BumbleBee.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 07 48 0d ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 49 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 49 8b 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 41 ba ?? ?? ?? ?? 4d ?? ?? ?? ?? ?? ?? 69 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 8b 88 ?? ?? ?? ?? 41 03 ca } //1
		$a_00_1 = {72 65 67 74 61 73 6b } //1 regtask
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}