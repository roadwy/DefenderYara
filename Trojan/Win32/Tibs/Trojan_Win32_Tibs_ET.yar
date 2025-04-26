
rule Trojan_Win32_Tibs_ET{
	meta:
		description = "Trojan:Win32/Tibs.ET,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 62 45 03 00 ?? 2d 61 45 03 00 83 ?? 01 75 f0 bf 01 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}