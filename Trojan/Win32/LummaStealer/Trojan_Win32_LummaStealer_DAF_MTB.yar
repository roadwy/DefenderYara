
rule Trojan_Win32_LummaStealer_DAF_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c0 e1 02 0f b6 c1 8b 4d fc c1 e9 06 0b c1 8b c8 c1 e9 03 33 c8 b8 ?? ?? ?? ?? f7 eb 03 d3 c1 fa 02 8b c2 c1 e8 1f 03 c2 2b c8 8d 04 cd 00 00 00 00 2b c1 03 c3 25 ?? ?? ?? ?? 79 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}