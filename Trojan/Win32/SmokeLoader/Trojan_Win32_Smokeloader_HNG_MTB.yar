
rule Trojan_Win32_Smokeloader_HNG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 fe 38 71 20 00 90 09 c0 00 [0-b9] b8 ?? ?? ?? ?? f7 [0-03] 8b [0-20] b8 ?? ?? ?? ?? f7 [0-03] 8b [0-20] b8 ?? ?? ?? ?? f7 [0-03] 8b [0-30] 33 ?? 81 3d ?? ?? ?? ?? 00 04 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}