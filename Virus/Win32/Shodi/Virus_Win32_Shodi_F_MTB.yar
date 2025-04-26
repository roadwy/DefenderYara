
rule Virus_Win32_Shodi_F_MTB{
	meta:
		description = "Virus:Win32/Shodi.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 44 24 28 50 53 53 68 99 19 40 00 68 00 04 00 00 53 ff 15 04 30 40 00 89 c7 53 57 ff d5 85 c0 74 de 6a 64 ff d6 57 ff 15 00 30 40 00 68 84 03 00 00 ff d6 57 ff 15 48 30 40 00 eb dd } //1
		$a_01_1 = {55 53 52 5f 53 68 6f 68 64 69 5f 50 68 6f 74 6f 5f 55 53 52 } //1 USR_Shohdi_Photo_USR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}