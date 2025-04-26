
rule Trojan_Win32_NSISInject_PRG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.PRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 8a ?? ?? ?? ?? ?? 88 55 ff 8b 45 e0 03 45 f4 8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 88 ?? ?? ?? ?? ?? 8b 45 f4 83 c0 01 99 b9 0d ?? ?? ?? f7 f9 89 55 f4 8b 55 f8 83 c2 01 89 55 f8 81 7d f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}