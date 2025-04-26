
rule Trojan_Win32_CobaltStrike_RAR_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d8 83 f3 01 0f af d8 c1 eb 08 32 1c 0f 8b 4d f0 8a d3 e8 69 ee ff ff 8b 4d e4 8b 45 f0 88 1c 0f 47 3b fe 72 cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}