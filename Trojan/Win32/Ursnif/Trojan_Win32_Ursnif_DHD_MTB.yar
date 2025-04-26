
rule Trojan_Win32_Ursnif_DHD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.DHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c1 0f af 05 ?? ?? ?? ?? 69 c0 59 5b 00 00 8d 48 dc 0f b7 c9 0f b7 f1 0f af f0 69 f6 59 5b 00 00 89 35 90 1b 00 8b c6 8b 35 ?? ?? ?? ?? 2b f2 03 f3 8b d6 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}