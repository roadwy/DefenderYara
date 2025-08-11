
rule Trojan_Win32_SmokeLoader_RGB_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 ff 75 f8 6a 00 6a 00 6a 00 6a 00 68 00 00 00 80 68 00 00 00 80 68 00 00 00 80 68 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}