
rule PWS_Win32_Sinowal_gen_L{
	meta:
		description = "PWS:Win32/Sinowal.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {9d 5d 9c 50 66 } //1
		$a_02_1 = {66 a9 01 28 58 0f 85 ?? ?? ?? ?? 9d 0f } //1
		$a_00_2 = {4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}