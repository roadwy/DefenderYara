
rule Trojan_Win32_ZBot_CRHG_MTB{
	meta:
		description = "Trojan:Win32/ZBot.CRHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 05 90 16 d1 14 4d 4f d0 14 c7 05 8c 16 d1 14 c8 11 d0 14 66 89 35 88 16 d1 14 c7 05 a0 16 d1 14 fb 4f d0 14 c7 05 9c 16 d1 14 b4 11 d0 14 66 89 35 98 16 d1 14 c7 05 b0 16 d1 14 b2 50 d0 14 c7 05 ac 16 d1 14 a0 11 d0 14 66 89 35 a8 16 d1 14 c7 05 c0 16 d1 14 a2 51 d0 14 c7 05 bc 16 d1 14 8c 11 d0 14 66 89 35 b8 16 d1 14 c7 05 d0 16 d1 14 92 52 d0 14 c7 05 cc 16 d1 14 78 11 d0 14 66 89 35 c8 16 d1 14 c7 05 e0 16 d1 14 bd 52 d0 14 c7 05 dc 16 d1 14 64 11 d0 14 66 89 35 d8 16 d1 14 c7 05 f0 16 d1 14 f7 52 d0 14 c7 05 ec 16 d1 14 50 11 d0 14 66 89 35 e8 16 d1 14 c7 05 00 17 d1 14 31 53 d0 14 c7 05 fc 16 d1 14 34 11 d0 14 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}