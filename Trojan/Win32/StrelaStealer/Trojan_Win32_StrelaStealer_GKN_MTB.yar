
rule Trojan_Win32_StrelaStealer_GKN_MTB{
	meta:
		description = "Trojan:Win32/StrelaStealer.GKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d8 35 98 45 cc 75 89 f2 81 f2 05 2a 48 b3 41 89 d2 41 21 f2 41 89 c3 41 21 f3 31 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}