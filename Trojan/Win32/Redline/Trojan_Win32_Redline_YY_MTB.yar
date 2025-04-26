
rule Trojan_Win32_Redline_YY_MTB{
	meta:
		description = "Trojan:Win32/Redline.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 e6 89 c8 29 d0 d1 e8 01 d0 c1 e8 06 6b c0 a5 01 c8 c1 e8 02 0f be 80 ?? ?? ?? ?? c1 e0 03 8d 04 40 0f bf d0 69 d2 ?? ?? ?? ?? c1 ea 10 01 c2 0f b7 c2 89 c2 c1 ea 0f c1 e8 05 01 d0 c0 e0 07 30 81 ?? ?? ?? ?? 83 c1 01 81 f9 7e 07 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}