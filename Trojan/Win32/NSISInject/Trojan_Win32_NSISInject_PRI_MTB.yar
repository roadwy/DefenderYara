
rule Trojan_Win32_NSISInject_PRI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.PRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55 ?? 8b ?? ?? 83 ?? 01 89 ?? ?? 81 7d ?? ?? ?? 00 00 } //1
		$a_03_1 = {83 c0 01 b9 0d 00 00 00 99 f7 f9 89 55 ?? 8b ?? ?? 83 ?? 01 89 ?? ?? 81 7d ?? ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}