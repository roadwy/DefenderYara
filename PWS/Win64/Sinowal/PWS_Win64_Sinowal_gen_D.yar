
rule PWS_Win64_Sinowal_gen_D{
	meta:
		description = "PWS:Win64/Sinowal.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 b8 f6 04 f1 4d 41 8b d4 48 8b cf e8 ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 41 b8 da 05 2d 08 41 8b d4 48 8b cf } //1
		$a_01_1 = {66 90 66 66 90 66 83 7a 48 18 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}