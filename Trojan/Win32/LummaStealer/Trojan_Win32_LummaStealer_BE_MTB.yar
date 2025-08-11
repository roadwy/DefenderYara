
rule Trojan_Win32_LummaStealer_BE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 54 24 0f 0f b6 54 24 0f 32 91 ?? ?? ?? ?? 88 54 24 0f 8b 54 24 08 81 c2 ?? ?? ?? ?? 89 54 24 08 83 c0 01 83 f8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}