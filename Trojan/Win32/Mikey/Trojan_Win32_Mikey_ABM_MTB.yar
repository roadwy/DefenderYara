
rule Trojan_Win32_Mikey_ABM_MTB{
	meta:
		description = "Trojan:Win32/Mikey.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a c3 02 45 08 30 87 ?? ?? ?? ?? 83 7d 08 03 ?? ?? 89 75 08 eb ?? ff 45 08 47 81 ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}