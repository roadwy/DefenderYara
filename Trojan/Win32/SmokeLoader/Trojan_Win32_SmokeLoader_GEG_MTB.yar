
rule Trojan_Win32_SmokeLoader_GEG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 03 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 ff 4d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}