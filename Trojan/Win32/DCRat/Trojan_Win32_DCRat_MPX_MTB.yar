
rule Trojan_Win32_DCRat_MPX_MTB{
	meta:
		description = "Trojan:Win32/DCRat.MPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d1 83 f2 19 8b 85 ?? ?? ?? ?? 0f af 50 04 8b 8d 4c fc ff ff 69 41 04 38 01 00 00 2b d0 8b 8d ?? ?? ?? ?? 89 11 8b 95 4c fc ff ff 89 95 ?? ?? ?? ?? 52 52 83 c4 04 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}