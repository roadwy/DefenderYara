
rule Trojan_Win32_Copak_P_MTB{
	meta:
		description = "Trojan:Win32/Copak.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 d6 81 ea ?? ?? ?? ?? 4e bf ?? ?? ?? ?? 29 f2 e8 ?? ?? ?? ?? 31 38 81 c0 ?? ?? ?? ?? 39 c8 75 e8 29 d2 81 ee ?? ?? ?? ?? c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}