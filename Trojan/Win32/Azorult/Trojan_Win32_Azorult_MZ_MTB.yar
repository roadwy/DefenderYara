
rule Trojan_Win32_Azorult_MZ_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 06 83 fd ?? 90 18 47 3b fd 90 18 8b ?? ?? ?? 8d [0-02] e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}