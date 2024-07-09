
rule Trojan_Win32_Copak_GPX_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {d8 85 40 00 [0-30] 31 [0-3f] ff 00 00 00 [0-5f] 81 ?? f4 01 00 00 75 05 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}