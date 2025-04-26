
rule Trojan_Win32_LummaStealer_AFZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.AFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 01 30 04 37 8b 44 24 18 2b c1 83 e0 fc 50 51 e8 ?? ?? ?? ?? 46 89 5c 24 18 59 59 89 5c 24 14 89 5c 24 18 3b 74 24 30 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}