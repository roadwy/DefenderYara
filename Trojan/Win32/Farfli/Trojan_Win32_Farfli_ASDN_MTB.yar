
rule Trojan_Win32_Farfli_ASDN_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 64 24 00 80 b4 05 ?? ?? ?? ?? ?? 40 3d c0 67 0f 00 75 } //5
		$a_03_1 = {6a 40 68 00 30 00 00 50 6a 00 ff 15 ?? ?? ?? ?? 8b f0 68 c0 67 0f 00 8d 85 ?? ?? ?? ff 50 56 e8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}