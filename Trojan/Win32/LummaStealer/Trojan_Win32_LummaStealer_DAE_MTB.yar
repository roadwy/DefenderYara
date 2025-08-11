
rule Trojan_Win32_LummaStealer_DAE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 2c 89 c2 81 e2 ?? ?? ?? ?? 89 eb 83 e3 02 09 d3 31 cb 81 f3 ?? ?? ?? ?? 8d 55 64 21 ca f7 d2 21 da 89 54 24 08 8b 4c 24 08 80 c1 74 88 0c 2c 45 48 83 fd 04 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}