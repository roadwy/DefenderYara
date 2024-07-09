
rule Trojan_Win32_Copak_CCGK_MTB{
	meta:
		description = "Trojan:Win32/Copak.CCGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c0 31 37 01 db 81 c7 ?? ?? ?? ?? 39 d7 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}