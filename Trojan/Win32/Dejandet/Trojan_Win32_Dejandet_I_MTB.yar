
rule Trojan_Win32_Dejandet_I_MTB{
	meta:
		description = "Trojan:Win32/Dejandet.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 01 08 83 c0 02 66 83 38 00 75 ef 90 0a 40 00 c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? [0-10] b9 ?? 00 00 00 66 01 08 83 c0 02 66 83 38 00 75 ef } //1
		$a_03_1 = {66 01 08 83 c0 02 66 83 38 00 75 ef 90 0a 40 00 c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? [0-10] b9 ?? 00 00 00 66 01 08 83 c0 02 66 83 38 00 75 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}