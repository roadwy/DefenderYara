
rule Trojan_Win32_LummaStealer_CCJY_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCJY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 0c 16 31 c1 0f af cb 0f be 44 16 ?? 31 c8 0f af c3 0f be 4c 16 ?? 31 c1 0f af cb 0f be 44 16 ?? 31 c8 0f af c3 83 c2 ?? 39 d7 75 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}