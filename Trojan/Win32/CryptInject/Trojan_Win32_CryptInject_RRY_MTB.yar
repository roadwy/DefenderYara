
rule Trojan_Win32_CryptInject_RRY_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.RRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 fa 03 82 1c 01 00 00 a3 ?? ?? ?? ?? 8b 86 bc 00 00 00 2b 86 8c 00 00 00 2d ec 7e 1f 00 09 42 44 8b 8e d0 00 00 00 8b 86 b4 00 00 00 31 04 39 83 c7 04 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 81 b4 00 00 00 81 ff 54 03 00 00 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}