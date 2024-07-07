
rule PWS_Win32_Sinowal_AC{
	meta:
		description = "PWS:Win32/Sinowal.AC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c 03 90 03 06 04 8d 90 01 02 ff ff 4d 90 01 01 51 ff 55 90 00 } //1
		$a_03_1 = {8b 45 f4 33 d2 b9 90 01 01 00 00 00 f7 f1 89 45 f4 8b 55 0c 03 55 f4 8a 02 88 45 f3 90 02 08 8b 4d 08 03 4d f4 8a 55 f3 88 11 ff 75 fc 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}