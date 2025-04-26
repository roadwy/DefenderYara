
rule Trojan_Win32_Rozena_GPC_MTB{
	meta:
		description = "Trojan:Win32/Rozena.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 30 80 36 27 89 5c 24 04 89 04 24 ff d7 83 ec 08 85 c0 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}