
rule Trojan_Win32_Copak_RJ_MTB{
	meta:
		description = "Trojan:Win32/Copak.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 fa f4 01 00 00 75 05 ba 00 00 00 00 81 c7 01 00 00 00 c3 09 f7 81 c7 01 00 00 00 eb c5 b0 01 df c3 09 fb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}