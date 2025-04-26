
rule Trojan_Win32_DarkMe_MBWQ_MTB{
	meta:
		description = "Trojan:Win32/DarkMe.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 3e 14 00 00 f0 30 00 00 ff ff ff 09 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 64 2b 00 11 cc 2c 00 11 dc 28 00 11 24 ed eb 10 2e ed eb } //2
		$a_01_1 = {39 ed eb 10 3a ed eb 10 00 00 f4 01 00 00 c6 40 14 00 00 00 00 00 20 45 00 11 10 3b 28 11 00 14 00 00 08 50 28 11 76 26 00 11 00 50 28 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}