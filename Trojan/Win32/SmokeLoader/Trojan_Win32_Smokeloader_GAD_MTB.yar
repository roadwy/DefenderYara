
rule Trojan_Win32_Smokeloader_GAD_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c6 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 c5 47 86 c8 61 ff 4c 24 ?? 0f 85 ?? ?? ?? ?? 81 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}