
rule Trojan_Win32_Neoreblamy_NIQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 40 89 45 f0 83 7d f0 ?? 7d 10 8b 45 f0 } //1
		$a_03_1 = {6a 04 59 6b c9 00 89 84 0d ?? ?? ff ff eb d6 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}