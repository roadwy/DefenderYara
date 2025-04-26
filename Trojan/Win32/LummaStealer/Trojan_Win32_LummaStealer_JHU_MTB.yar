
rule Trojan_Win32_LummaStealer_JHU_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.JHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 4c 24 10 8b 54 24 14 88 44 3c 18 88 5c 2c ?? 0f b6 44 3c ?? 03 c6 0f b6 c0 0f b6 44 04 ?? 30 04 0a 41 89 4c 24 10 3b 8c 24 24 02 00 00 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}