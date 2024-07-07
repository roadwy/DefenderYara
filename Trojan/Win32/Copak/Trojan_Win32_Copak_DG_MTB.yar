
rule Trojan_Win32_Copak_DG_MTB{
	meta:
		description = "Trojan:Win32/Copak.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 1f 68 5d 37 18 d7 5e 81 c7 04 00 00 00 29 c1 81 ee 02 5f 26 7a 39 d7 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}