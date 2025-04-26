
rule Trojan_Win32_Zenpak_AMBC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 1f 8b 55 ec 8b 5d d4 32 0c 1a 8b 55 e8 88 0c 1a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}