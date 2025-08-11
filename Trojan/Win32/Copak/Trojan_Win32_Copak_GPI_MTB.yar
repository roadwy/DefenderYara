
rule Trojan_Win32_Copak_GPI_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 b3 43 00 [0-10] e8 [0-20] 31 [0-40] 75 [0-40] 81 ?? ff 00 00 00 [0-40] 81 ?? f4 01 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}