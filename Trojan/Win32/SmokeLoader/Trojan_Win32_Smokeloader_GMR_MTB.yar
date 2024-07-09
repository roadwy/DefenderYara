
rule Trojan_Win32_Smokeloader_GMR_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c3 31 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 c7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}