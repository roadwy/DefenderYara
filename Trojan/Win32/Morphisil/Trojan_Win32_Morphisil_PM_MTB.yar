
rule Trojan_Win32_Morphisil_PM_MTB{
	meta:
		description = "Trojan:Win32/Morphisil.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e0 30 00 00 8b 45 ?? 03 45 ?? c6 00 00 8b 4d ?? 03 4d ?? 0f b6 11 8b 45 ?? 03 45 ?? 0f b6 08 8d 54 11 ?? 8b 45 ?? 03 45 ?? 88 10 8b 4d ?? 03 4d ?? 0f b6 11 83 ea 0e 8b 45 ?? 03 45 ?? 88 10 c7 45 ?? 01 00 00 00 8b 4d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}