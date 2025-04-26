
rule PWS_Win32_Sinowal_F{
	meta:
		description = "PWS:Win32/Sinowal.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 01 45 fc 8b 06 8b 7d f4 33 c7 [0-0c] 83 f9 00 [0-06] 0f 84 } //1
		$a_03_1 = {8b 45 c4 83 c0 01 89 45 c4 [0-03] e9 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}