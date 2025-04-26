
rule Trojan_Win32_Ursnif_PS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c3 0f b7 f8 8b 4c 24 ?? 8b 44 24 ?? 83 44 24 ?? ?? 05 ?? ?? ?? ?? 0f b7 f7 83 c6 ?? 89 01 03 f2 89 44 24 ?? 8d 4b ?? a3 ?? ?? ?? ?? 03 ce ff 4c 24 ?? 0f b7 f9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}