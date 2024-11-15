
rule Trojan_Win32_Denes_GE_MTB{
	meta:
		description = "Trojan:Win32/Denes.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 ff cf 31 79 b6 a2 ?? ?? ?? ?? 18 65 83 49 } //5
		$a_03_1 = {50 ff b4 24 ?? ?? ?? ?? ff b4 24 ?? ?? ?? ?? ff 74 24 ?? ff 75 00 68 ?? ?? ?? ?? ff 35 } //5
		$a_80_2 = {5c 6d 69 63 72 6f 73 6f 66 74 5c 6c 73 61 73 73 2e 65 78 65 } //\microsoft\lsass.exe  1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=11
 
}