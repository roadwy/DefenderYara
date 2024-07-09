
rule Trojan_Win32_Copak_GNW_MTB{
	meta:
		description = "Trojan:Win32/Copak.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f 31 0e 81 ef ?? ?? ?? ?? 01 fa 81 c6 ?? ?? ?? ?? 09 fa 81 c2 ?? ?? ?? ?? 39 c6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}