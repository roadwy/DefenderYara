
rule Trojan_Win32_Copak_SPE_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 d8 85 40 00 e8 ?? ?? ?? ?? 09 f6 42 31 03 4e 01 d2 43 01 d2 39 cb 75 e7 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}