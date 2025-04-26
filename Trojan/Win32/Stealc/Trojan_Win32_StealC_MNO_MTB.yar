
rule Trojan_Win32_StealC_MNO_MTB{
	meta:
		description = "Trojan:Win32/StealC.MNO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 08 0f 66 1f 00 00 00 00 00 e9 00 20 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}