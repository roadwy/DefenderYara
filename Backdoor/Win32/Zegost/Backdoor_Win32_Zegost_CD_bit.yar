
rule Backdoor_Win32_Zegost_CD_bit{
	meta:
		description = "Backdoor:Win32/Zegost.CD!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 5d fc c6 45 90 01 01 56 c6 45 90 01 01 49 c6 45 90 01 01 44 c6 45 90 01 01 3a c6 45 90 01 01 32 c6 45 90 01 01 30 c6 45 90 01 01 31 c6 45 90 00 } //1
		$a_03_1 = {c6 45 f6 6c c6 45 f7 44 c6 45 f8 64 ff 35 90 01 04 c6 45 f9 6f c6 45 fa 73 c6 45 fb 53 c6 45 fc 74 c6 45 fd 6f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}