
rule Trojan_Win32_Stealerc_NS_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 e8 25 04 00 00 8b f0 39 3e 74 13 56 e8 ?? ?? ?? ?? 59 84 c0 74 08 ff 36 e8 ?? ?? ?? ?? 59 e8 28 05 00 00 0f b7 f0 e8 d5 53 00 00 56 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}