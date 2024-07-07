
rule Trojan_Win32_Redline_NEAZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.NEAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 8b 4d c8 0f b6 1c 31 8a c3 02 45 cf 88 04 31 } //5
		$a_01_1 = {83 c4 04 8b 45 c8 28 1c 30 46 eb a4 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}