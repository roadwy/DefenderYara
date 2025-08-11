
rule Trojan_Win32_ZLoad_AHB_MTB{
	meta:
		description = "Trojan:Win32/ZLoad.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca 80 c2 ?? 32 54 0c 04 80 c2 ?? 88 54 0c 04 41 83 f9 ?? 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}