
rule Trojan_Win32_Pikabot_SPDQ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.SPDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {45 6b 61 67 66 67 4d 6b 6c 67 45 58 49 48 4a 50 45 54 71 } //1 EkagfgMklgEXIHJPETq
		$a_81_1 = {47 79 43 53 6f 44 45 47 53 47 55 7a 4a } //1 GyCSoDEGSGUzJ
		$a_81_2 = {4a 68 68 5a 51 6e 4d 66 50 43 6f 64 67 47 67 } //1 JhhZQnMfPCodgGg
		$a_81_3 = {4c 6f 75 59 6b 4b 58 64 } //1 LouYkKXd
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}