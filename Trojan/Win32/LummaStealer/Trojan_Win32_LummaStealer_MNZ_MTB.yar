
rule Trojan_Win32_LummaStealer_MNZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 da 83 e2 1e 0f b6 54 14 0c 32 54 1d 20 88 54 1d 00 8d 53 01 83 e2 1f 0f b6 54 14 0c 32 54 1d 21 88 54 1d 01 83 c3 02 39 d9 75 d4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}