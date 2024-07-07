
rule Trojan_Win32_Morphisil_PM_MTB{
	meta:
		description = "Trojan:Win32/Morphisil.PM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e0 30 00 00 8b 45 90 01 01 03 45 90 01 01 c6 00 00 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 8b 45 90 01 01 03 45 90 01 01 0f b6 08 8d 54 11 90 01 01 8b 45 90 01 01 03 45 90 01 01 88 10 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 83 ea 0e 8b 45 90 01 01 03 45 90 01 01 88 10 c7 45 90 01 01 01 00 00 00 8b 4d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}