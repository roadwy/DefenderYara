
rule Trojan_Win32_Zenpak_RDO_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 0f b6 c0 5d c3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}