
rule Trojan_Win32_Copak_GPAC_MTB{
	meta:
		description = "Trojan:Win32/Copak.GPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 b3 43 00 [0-30] 31 [0-3f] ff 00 00 00 [0-5f] 81 ?? f4 01 00 00 75 05 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}