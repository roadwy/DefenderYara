
rule Trojan_Win32_SmokeLoader_EAQP_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.EAQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 8b 0d ?? ?? ?? ?? 8a 8c 01 d6 38 00 00 8b 15 ?? ?? ?? ?? 88 0c 02 c9 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}