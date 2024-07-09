
rule Trojan_Win32_Azorult_RDV_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 0f b7 1d ?? ?? ?? ?? 81 e3 ff 7f 00 00 81 3d ?? ?? ?? ?? e7 08 00 00 75 ?? 6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 30 1c 3e 83 fd 19 75 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}