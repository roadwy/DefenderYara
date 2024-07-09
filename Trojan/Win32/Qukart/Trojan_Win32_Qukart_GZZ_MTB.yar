
rule Trojan_Win32_Qukart_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 4b 4a 6b 45 6b 76 4d 71 } //10
		$a_03_1 = {42 65 4a 4b 48 7a ?? 75 ?? 35 ?? ?? ?? ?? 03 00 00 36 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}