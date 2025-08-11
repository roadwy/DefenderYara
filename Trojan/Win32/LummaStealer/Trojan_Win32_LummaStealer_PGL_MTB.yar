
rule Trojan_Win32_LummaStealer_PGL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.PGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 ca 21 f2 89 d1 f7 d1 83 e1 ?? 83 f2 ?? 8d 0c 4a 88 8c 04 ?? ?? ?? ?? 40 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}