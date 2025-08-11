
rule Trojan_Win32_LummaStealer_DAD_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c1 02 81 e1 ?? ?? ?? ?? 81 e7 ?? ?? ?? ?? 09 cf 81 f7 ?? ?? ?? ?? 09 f7 f7 d7 21 ef 8b 2c 24 89 7c 24 10 8b 4c 24 10 80 c1 f6 88 4c 04 09 40 4d 83 f8 07 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}