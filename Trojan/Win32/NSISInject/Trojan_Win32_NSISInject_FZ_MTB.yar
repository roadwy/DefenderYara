
rule Trojan_Win32_NSISInject_FZ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 83 c2 01 89 55 ?? 81 7d ?? ?? ?? ?? ?? 7d 90 09 0e 00 8b 45 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}