
rule Trojan_Win32_LummaStealer_ABL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 fa 81 ca ?? ?? ?? ?? 21 da 09 f2 d1 ea 89 fe 83 e7 01 f7 df 81 e7 ?? ?? ?? ?? 33 3c 81 31 d7 89 bc 81 ?? ?? ?? ?? 40 3d e1 04 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}