
rule Trojan_Win32_CobaltStrike_GXL_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.GXL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 02 83 f0 ?? 8b 4d ?? 03 4d ?? 88 01 } //5
		$a_03_1 = {03 fa d0 ba ?? ?? ?? ?? 3c c2 70 02 5d 55 ec ?? ?? fa fa 34 fa } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}