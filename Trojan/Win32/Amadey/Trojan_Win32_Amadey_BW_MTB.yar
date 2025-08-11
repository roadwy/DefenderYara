
rule Trojan_Win32_Amadey_BW_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c7 50 6a 00 e8 ?? ?? ?? ?? 5a 2b d0 31 13 83 45 } //4
		$a_01_1 = {04 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}