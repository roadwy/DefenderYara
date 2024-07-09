
rule Trojan_Win32_Smokeloader_GWF_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 4d 8f 0f b6 55 8f a1 ?? ?? ?? ?? 03 45 84 0f be 08 33 ca 8b 15 ?? ?? ?? ?? 03 55 84 88 0a e9 15 ff ff ff } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}