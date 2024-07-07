
rule Adware_MacOS_Ketin_A_MTB{
	meta:
		description = "Adware:MacOS/Ketin.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f4 e5 af a5 e4 bf df e1 f0 e9 eb e5 f9 bd e3 b5 e5 b4 e4 b9 e3 b2 e6 b8 b5 b0 e3 b2 e4 e1 b0 b6 b7 b9 b0 b0 b8 b0 e5 e3 b5 b3 e3 e4 b5 b6 b0 e4 b6 e3 b1 b4 b7 e2 80 c7 c5 d4 80 c4 c5 c2 d5 c7 a0 80 a5 c0 80 c4 c5 c2 d5 c7 a0 80 e4 ef f7 ee ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}