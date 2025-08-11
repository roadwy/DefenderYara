
rule Trojan_Win32_LummaStealer_DW_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 cf 81 e7 ?? ?? ?? ?? 81 cf ?? ?? ?? ?? 31 f7 21 cb 8d 34 2b 46 8b 1c 24 09 fe 8d 04 50 89 f2 f7 d2 09 c2 8d 04 16 40 89 44 24 1c 8b 44 24 1c 04 34 88 84 0c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}