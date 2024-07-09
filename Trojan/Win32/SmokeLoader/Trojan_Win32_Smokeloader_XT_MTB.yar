
rule Trojan_Win32_Smokeloader_XT_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.XT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 8b 45 80 8d 1c 30 e8 ?? ?? ?? ?? 30 03 81 ff ?? ?? ?? ?? 0f 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}