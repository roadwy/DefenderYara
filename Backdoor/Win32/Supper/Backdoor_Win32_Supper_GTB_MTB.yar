
rule Backdoor_Win32_Supper_GTB_MTB{
	meta:
		description = "Backdoor:Win32/Supper.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 04 1f 48 33 45 ?? 48 89 04 1e e8 } //5
		$a_03_1 = {48 8b 07 48 89 45 ?? 48 83 c7 ?? 48 31 db e8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}