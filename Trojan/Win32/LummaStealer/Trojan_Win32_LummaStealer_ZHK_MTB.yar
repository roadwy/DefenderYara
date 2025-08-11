
rule Trojan_Win32_LummaStealer_ZHK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZHK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 78 87 b6 9f 54 b7 7d a9 3d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_ZHK_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.ZHK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 81 3e 4d 5a 0f 85 67 06 00 00 8b 7e 3c 81 3c 37 50 45 00 00 0f 85 c8 06 00 00 89 74 24 04 01 f7 66 81 7f 04 64 86 0f 85 10 07 00 00 6a 04 68 00 30 00 00 ff 77 50 6a 00 e8 d7 5d 01 00 85 c0 8b 74 24 3c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}