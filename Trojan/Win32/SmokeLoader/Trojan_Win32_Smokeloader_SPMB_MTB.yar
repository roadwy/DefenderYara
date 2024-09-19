
rule Trojan_Win32_Smokeloader_SPMB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.SPMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8a 4d fc 03 c2 30 08 42 3b 55 0c 7c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}