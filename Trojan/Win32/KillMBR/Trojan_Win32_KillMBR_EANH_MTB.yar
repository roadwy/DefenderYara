
rule Trojan_Win32_KillMBR_EANH_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EANH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be d2 0f af d1 88 94 05 f8 59 f1 ff 40 3d 00 a6 0e 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}