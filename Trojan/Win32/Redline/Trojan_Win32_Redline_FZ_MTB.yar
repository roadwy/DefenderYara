
rule Trojan_Win32_Redline_FZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.FZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 d0 08 d4 08 c1 24 eb 08 c6 f6 d1 30 e6 b8 [0-04] 08 f1 88 0c 2f 3d [0-04] 0f 8e } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}