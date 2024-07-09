
rule Trojan_Win32_Amadey_ADZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ADZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 c6 44 24 ?? 83 8a 44 34 ?? 34 a9 0f b6 c0 66 89 44 74 ?? 46 83 fe 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}