
rule Trojan_Win32_Povertystealer_ASK_MTB{
	meta:
		description = "Trojan:Win32/Povertystealer.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c1 83 e1 1f 0f b6 89 ?? ?? ?? 00 30 0c 06 40 3d ?? ?? ?? 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}