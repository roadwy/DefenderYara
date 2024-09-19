
rule Trojan_Win32_Smokeloader_GZM_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 30 08 83 ff 0f ?? ?? 53 53 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}