
rule Trojan_Win32_Parallax_PA_MTB{
	meta:
		description = "Trojan:Win32/Parallax.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {57 8b 7c 24 10 33 c0 85 ff 7e 4c 53 8b 5c 24 10 56 8b 74 24 10 2b de eb 07 8d a4 24 00 00 00 00 8b 0c 85 ?? ?? ?? 00 33 0c 33 89 0e 85 c0 74 1f 8b 15 ?? ?? ?? 00 33 15 ?? ?? ?? 00 0f bf 0d ?? ?? ?? 00 3b ca 7e 07 c6 05 ?? ?? ?? 00 ac 40 83 c6 04 4f 75 cb } //10
		$a_02_1 = {56 66 c7 45 ?? 6f 63 66 c7 45 ?? 41 6c 66 c7 45 ?? 72 74 c6 45 ?? 6c } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1) >=11
 
}