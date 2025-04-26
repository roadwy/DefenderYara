
rule Trojan_Win32_Cryptinject_MX_MTB{
	meta:
		description = "Trojan:Win32/Cryptinject.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d3 c1 ea 05 03 95 c8 fb ff ff 81 3d ?? ?? ?? ?? 31 09 00 00 89 95 d8 fb ff ff } //1
		$a_02_1 = {81 f3 07 eb dd 13 81 6d ?? 52 ef 6f 62 2d f3 32 05 00 81 6d ?? 68 19 2a 14 81 45 ?? be 08 9a 76 8b 45 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Cryptinject_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Cryptinject.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 f3 07 eb dd 13 81 6c 24 ?? 52 ef 6f 62 2d f3 32 05 00 81 6c 24 ?? 68 19 2a 14 81 44 24 ?? be 08 9a 76 8b 44 24 } //1
		$a_02_1 = {8b 54 24 20 c1 ea 05 03 54 24 38 89 54 24 ?? 3d 31 09 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}