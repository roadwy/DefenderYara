
rule Backdoor_Win32_Kaser_A{
	meta:
		description = "Backdoor:Win32/Kaser.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 61 6b 65 72 45 76 65 6e 74 } //5 SakerEvent
		$a_01_1 = {4a 75 73 74 54 65 6d 70 46 75 6e } //5 JustTempFun
		$a_01_2 = {66 89 55 f8 c6 45 e8 47 c6 45 eb 43 c6 45 f2 50 } //1
		$a_01_3 = {66 89 55 ec c6 45 dc 47 c6 45 df 43 c6 45 e6 50 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}