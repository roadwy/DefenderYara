
rule Trojan_Win32_Ursnif_AAJ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b ca 81 e9 70 48 00 00 81 c7 c0 54 60 01 8b f1 89 3d ?? ?? ?? ?? 8d 04 36 89 7d 00 39 05 ?? ?? ?? ?? 73 90 0a 42 00 03 c2 a3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}