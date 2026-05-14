
rule Trojan_Win32_Zusy_ABZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c3 89 da 8b 45 f0 83 c0 04 89 94 85 ?? ?? ?? ?? 8b 45 f0 83 c0 04 8b 94 85 ?? ?? ?? ?? 8b 45 f0 8d 0c 85 ?? ?? ?? ?? 8b 45 0c 01 c8 89 10 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}