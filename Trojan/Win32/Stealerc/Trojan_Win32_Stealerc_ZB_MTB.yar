
rule Trojan_Win32_Stealerc_ZB_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 14 1e 83 ff 0f } //1
		$a_01_1 = {46 3b f7 7c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}