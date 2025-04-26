
rule Trojan_Win32_Zenpack_MKV_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 fe 81 e6 ?? ?? ?? ?? 8b 7d ?? 8a 1c 0f 8b 7d ?? 32 1c 37 8b 75 ?? 88 1c 0e 81 c1 ?? ?? ?? ?? 8b 75 ?? 39 f1 8b 75 ?? 89 4d ?? 89 75 ?? 89 55 ?? 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}