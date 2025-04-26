
rule Adware_Win32_Neoreklami_RT_MTB{
	meta:
		description = "Adware:Win32/Neoreklami.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 7a 75 53 47 43 51 70 78 5a 6c 78 47 52 45 58 43 51 70 56 46 48 4d 4f 56 46 50 77 73 4d 57 67 4f 71 } //1 hzuSGCQpxZlxGREXCQpVFHMOVFPwsMWgOq
		$a_81_1 = {41 56 4b 66 61 76 66 6c 58 54 76 4e 68 46 65 40 73 74 64 40 40 } //1 AVKfavflXTvNhFe@std@@
		$a_81_2 = {5a 70 68 52 4e 4c 74 59 42 43 4d 72 51 7a 63 79 59 65 77 72 55 4e 58 72 75 47 53 6e 49 45 6c 78 7a 72 7a 4c 6b 44 65 6a 78 } //1 ZphRNLtYBCMrQzcyYewrUNXruGSnIElxzrzLkDejx
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}