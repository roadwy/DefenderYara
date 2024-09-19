
rule Trojan_Win32_Symmi_MBXS_MTB{
	meta:
		description = "Trojan:Win32/Symmi.MBXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 2e 64 6c 6c 00 44 6c 6c 43 6d 64 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}