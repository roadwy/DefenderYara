
rule Trojan_Win32_LummaC_GTN_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 4d c3 8b 5d ?? 30 ca 8b 55 ?? 0f 45 c7 89 5d ?? 89 55 ?? 8b 55 ?? 89 55 ?? 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}