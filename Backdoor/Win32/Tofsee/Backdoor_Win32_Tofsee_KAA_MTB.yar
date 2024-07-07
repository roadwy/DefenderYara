
rule Backdoor_Win32_Tofsee_KAA_MTB{
	meta:
		description = "Backdoor:Win32/Tofsee.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 65 79 75 68 69 62 6f 78 6f 77 69 } //deyuhiboxowi  1
		$a_80_1 = {77 6f 63 69 74 61 78 61 68 75 74 65 78 6f 64 65 7a 75 72 61 } //wocitaxahutexodezura  1
		$a_80_2 = {74 75 64 69 7a 75 6b 65 64 69 } //tudizukedi  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}