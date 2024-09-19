
rule Trojan_Win32_LummaStealer_GPH_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.GPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0f 05 ?? ?? ?? ?? 31 c8 89 45 ?? 8b 45 ?? 04 ?? 8b 4d ?? 88 04 0f ff 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}