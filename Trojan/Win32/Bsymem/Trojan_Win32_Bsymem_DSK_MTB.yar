
rule Trojan_Win32_Bsymem_DSK_MTB{
	meta:
		description = "Trojan:Win32/Bsymem.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d fc 03 ce 30 01 b8 01 00 00 00 29 45 fc 39 7d fc 7d 90 09 05 00 e8 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}