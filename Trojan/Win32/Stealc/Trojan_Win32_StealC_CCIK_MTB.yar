
rule Trojan_Win32_StealC_CCIK_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c7 30 08 83 fb 0f 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}