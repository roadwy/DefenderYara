
rule Trojan_Win32_StealC_IZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.IZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4d fc 8b 45 08 30 0c 07 83 fb 0f 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}