
rule Trojan_Win32_Copak_GP_MTB{
	meta:
		description = "Trojan:Win32/Copak.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {4f 09 cf 31 1e 01 f9 81 c7 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 09 c9 81 ef ?? ?? ?? ?? 39 d6 75 d6 b9 ?? ?? ?? ?? 41 c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}