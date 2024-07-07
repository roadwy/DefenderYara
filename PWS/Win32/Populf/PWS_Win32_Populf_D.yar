
rule PWS_Win32_Populf_D{
	meta:
		description = "PWS:Win32/Populf.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 01 00 00 00 e8 79 f2 ff ff 8b 55 ec b8 58 bc 40 00 b9 90 01 01 97 40 00 e8 1b a9 ff ff 8d 55 e8 b8 01 00 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}