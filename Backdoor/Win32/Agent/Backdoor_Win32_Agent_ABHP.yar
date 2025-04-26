
rule Backdoor_Win32_Agent_ABHP{
	meta:
		description = "Backdoor:Win32/Agent.ABHP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {31 c0 0f a2 85 c0 0f 84 ?? ?? ?? ?? b8 01 00 00 00 0f a2 f6 c6 01 74 } //1
		$a_02_1 = {68 63 d6 00 00 e8 ?? ?? ?? ?? 66 89 45 da 6a 00 e8 ?? ?? ?? ?? 89 45 dc } //1
		$a_00_2 = {00 62 61 63 6b 64 6f 6f 72 20 73 65 72 76 69 63 65 00 } //1
		$a_00_3 = {00 62 69 6e 64 00 63 6d 64 00 } //1 戀湩d浣d
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}