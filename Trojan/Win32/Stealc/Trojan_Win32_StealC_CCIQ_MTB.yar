
rule Trojan_Win32_StealC_CCIQ_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 4d fc 03 c6 30 08 46 3b 75 0c 7c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}