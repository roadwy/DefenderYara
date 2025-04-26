
rule Backdoor_Win64_Supper_A_ldr{
	meta:
		description = "Backdoor:Win64/Supper.A!ldr,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 04 1f 48 33 45 f0 48 89 04 1e e8 ?? ?? ?? ?? 48 3b 45 e0 0f 83 ?? ?? ?? ?? 48 31 c9 51 48 8d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}