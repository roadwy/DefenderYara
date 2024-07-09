
rule PWS_Win32_Nemqe_B{
	meta:
		description = "PWS:Win32/Nemqe.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 2e 64 6c 6c 00 4c 70 6b } //1 湉敪瑣搮汬䰀歰
		$a_03_1 = {6a 2c 8b d8 53 e8 ?? ?? 00 00 83 c4 10 85 c0 75 aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}