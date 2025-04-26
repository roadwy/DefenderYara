
rule Trojan_Win32_NsInject_CT_MTB{
	meta:
		description = "Trojan:Win32/NsInject.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c9 8d a4 24 00 00 00 00 8a 14 8d ?? ?? ?? ?? 80 c2 ?? 88 14 01 83 c1 01 81 f9 ?? ?? 00 00 7c e8 8d 0c 24 51 05 ?? ?? 00 00 ff d0 b8 ?? ?? 00 00 83 c4 1c c3 } //1
		$a_02_1 = {8b 4c 24 04 33 c0 eb ?? 8d a4 24 00 00 00 00 90 05 10 01 90 8a 14 85 ?? ?? ?? ?? 80 c2 ?? 88 14 08 83 c0 01 3d ?? ?? 00 00 7c ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}