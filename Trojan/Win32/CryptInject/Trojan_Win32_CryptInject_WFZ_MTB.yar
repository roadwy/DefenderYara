
rule Trojan_Win32_CryptInject_WFZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.WFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 1c 38 83 c7 04 0f af 5e 58 a1 ?? ?? ?? ?? 8b d3 c1 ea 10 88 14 01 b8 d8 f3 1b 00 ff 05 ?? ?? ?? ?? 8b d3 2b 86 b4 00 00 00 01 46 64 8b 8e 84 00 00 00 33 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 84 6b fc fe c1 ea 08 03 c1 a3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}