
rule Backdoor_Win32_Tofsee_B_sys{
	meta:
		description = "Backdoor:Win32/Tofsee.B!sys,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {7e 68 8d 84 3d ?? eb ff ff 80 78 ff 32 75 56 80 38 35 75 51 80 78 01 30 75 4b ff 75 ?? 8d 85 ?? ff ff ff 50 8d 4d ?? e8 } //1
		$a_02_1 = {74 1a 83 ce ff 8d 0c 06 8a 8c 0d e0 fe ff ff 80 f1 c5 48 88 8c 06 ?? ?? 40 00 75 e9 33 c0 89 45 fc 8d 45 f8 50 68 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}