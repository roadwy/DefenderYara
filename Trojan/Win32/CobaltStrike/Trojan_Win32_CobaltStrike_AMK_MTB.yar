
rule Trojan_Win32_CobaltStrike_AMK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 0f ef c8 0f 11 88 28 40 00 10 0f 10 80 38 40 00 10 0f 28 ca 66 0f ef c2 0f 11 80 38 40 00 10 0f 10 80 48 40 00 10 66 0f ef c8 0f 11 88 48 40 00 10 0f 10 80 58 40 00 10 } //1
		$a_01_1 = {80 b0 28 40 00 10 e2 40 3d 10 38 03 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}