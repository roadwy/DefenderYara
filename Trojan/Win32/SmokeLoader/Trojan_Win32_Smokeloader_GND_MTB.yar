
rule Trojan_Win32_Smokeloader_GND_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 45 f8 30 04 3b 83 7d 08 0f 59 ?? ?? 56 ff 15 ?? ?? ?? ?? 56 56 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}