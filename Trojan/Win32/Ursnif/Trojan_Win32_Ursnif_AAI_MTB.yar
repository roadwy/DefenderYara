
rule Trojan_Win32_Ursnif_AAI_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c1 e0 58 6f 01 89 4c 24 18 89 0b 8b 5c 24 24 89 0d ?? ?? ?? ?? 8d 0c 33 8d 0c 4d ?? ?? ?? ?? 03 cb 81 3d ?? ?? ?? ?? 6e 1e 00 00 89 4c 24 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}