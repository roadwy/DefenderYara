
rule Trojan_Win32_LummaStealer_ZSK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZSK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {56 5c 7f 62 3d fe 26 56 28 74 7b 3d 70 62 9f 33 75 e4 0f b6 4c 24 6e 80 7c 24 6f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}