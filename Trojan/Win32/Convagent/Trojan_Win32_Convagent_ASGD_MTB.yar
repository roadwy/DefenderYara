
rule Trojan_Win32_Convagent_ASGD_MTB{
	meta:
		description = "Trojan:Win32/Convagent.ASGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 59 8b 45 ?? 83 c0 64 89 45 ?? 83 6d ?? 64 8b 45 bc 8a 4d ?? 03 c7 30 08 83 fb 0f 75 } //4
		$a_03_1 = {46 81 fe cb ed 36 00 0f 8c ?? ?? ff ff 5e c9 c3 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}