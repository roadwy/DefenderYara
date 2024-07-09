
rule Backdoor_Win32_Tofsee_MML_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.MML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 86 38 bf 82 00 30 04 2f 83 6c 24 ?? 01 8b 7c 24 ?? 85 ff 0f 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}