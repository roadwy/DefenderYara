
rule Trojan_Win32_LummaStealer_SPDC_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SPDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d0 00 c2 0f b6 d2 0f b6 8c 15 ?? ?? ?? ?? 88 8c 35 ?? ?? ?? ?? 89 55 d0 88 84 15 ?? ?? ?? ?? 02 84 35 ?? ?? ?? ?? 0f b6 c0 0f b6 84 05 ?? ?? ?? ?? 8b 4d 08 8b 55 d8 30 04 11 42 89 55 d8 39 55 0c 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}