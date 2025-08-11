
rule Trojan_Win32_KillMBR_EABR_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.EABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ca 88 8c 05 78 56 fc ff 40 3d 80 a9 03 00 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}