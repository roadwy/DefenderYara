
rule Trojan_Win32_LummaStealer_CCIH_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 95 c2 8b 04 95 ?? ?? ?? ?? ba ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 01 c2 42 31 c0 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}