
rule Trojan_Win32_LummaStealer_MJ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 8b 44 24 10 c1 e9 05 03 4c 24 30 81 3d } //00 00 
	condition:
		any of ($a_*)
 
}