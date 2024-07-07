
rule PWS_Win32_Sinowal_gen_H{
	meta:
		description = "PWS:Win32/Sinowal.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 04 1b 40 00 ff 25 90 01 02 40 00 90 02 07 ff 25 90 00 } //1
		$a_03_1 = {ff 15 14 a0 40 00 ff 25 90 01 02 40 00 90 02 07 ff 25 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}