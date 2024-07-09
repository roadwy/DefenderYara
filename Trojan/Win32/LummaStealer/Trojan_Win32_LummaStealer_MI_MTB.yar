
rule Trojan_Win32_LummaStealer_MI_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c6 89 44 24 10 8b 44 24 1c 31 44 24 10 2b 5c 24 10 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 34 01 44 24 18 2b 7c 24 18 ff 4c 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}