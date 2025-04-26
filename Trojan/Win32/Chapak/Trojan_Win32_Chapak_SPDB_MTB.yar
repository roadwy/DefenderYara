
rule Trojan_Win32_Chapak_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Chapak.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 33 db 8b 45 f4 33 d1 03 45 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}