
rule Trojan_Win32_Amadey_ASGK_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ASGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 45 c4 50 89 7d c4 e8 ?? ?? ?? ff 8a 45 c4 30 04 33 83 7d 08 0f 59 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}