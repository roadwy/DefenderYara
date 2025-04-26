
rule Trojan_Win32_StealC_RDG_MTB{
	meta:
		description = "Trojan:Win32/StealC.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f4 8b 45 e8 c1 e8 05 89 45 f8 8b 4d fc 33 db 33 4d f4 8b 45 f8 03 45 d0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}