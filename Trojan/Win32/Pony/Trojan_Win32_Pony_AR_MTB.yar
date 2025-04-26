
rule Trojan_Win32_Pony_AR_MTB{
	meta:
		description = "Trojan:Win32/Pony.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 0c eb ae 3a 8d 2d 25 42 81 ac 69 3f 8f 2d ae cc 29 c4 1a 32 8d 2d f6 b6 08 ed ae 3f 8d c5 1a 3b 8d 2d 27 f7 d4 04 61 bc 64 2f af fe 04 60 ba d7 f2 df 51 c0 eb a6 b2 30 eb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}