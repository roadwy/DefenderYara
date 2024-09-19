
rule Trojan_Win32_SmokeLoader_YQT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.YQT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 8a 4d fc 03 c6 30 08 83 7d 0c 0f 75 0d 57 ff 75 0c ff d3 57 ff 15 ?? ?? ?? ?? 46 3b 75 0c 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}