
rule Backdoor_Win64_Supper_B{
	meta:
		description = "Backdoor:Win64/Supper.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 7d 10 ff 3f 0f ?? ?? ?? ?? ?? 0f b7 45 10 48 98 48 8d 14 c5 00 00 00 00 48 8d } //1
		$a_03_1 = {81 7d fc ff 3f 00 00 0f ?? ?? ?? ?? ?? 48 8b 05 5e 3e 02 00 48 85 c0 74 ?? 48 8b 05 52 3e 02 00 48 89 c1 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}