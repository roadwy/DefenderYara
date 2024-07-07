
rule Trojan_Win32_Redline_GMP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 e2 0b ca 88 4d 90 01 01 0f b6 45 90 01 01 33 45 90 01 01 88 45 90 01 01 0f b6 4d 90 01 01 81 c1 90 01 04 88 4d 90 01 01 0f b6 55 90 01 01 83 f2 90 01 01 88 55 90 01 01 0f b6 45 90 01 01 03 45 90 01 01 88 45 90 01 01 0f b6 4d 90 01 01 f7 d1 88 4d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}