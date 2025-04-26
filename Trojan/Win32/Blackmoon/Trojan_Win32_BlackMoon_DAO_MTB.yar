
rule Trojan_Win32_BlackMoon_DAO_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.DAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c8 b7 a3 ac d4 ad d2 f2 bf c9 c4 dc ca c7 a3 ba 00 bc c7 b4 ed c3 dc c2 eb a3 bb ce aa c7 f8 b7 d6 b4 f3 d0 a1 d0 b4 a3 bb ce b4 bf aa c6 f4 d0 a1 bc fc c5 cc a1 a3 } //1
		$a_01_1 = {d1 c9 e8 d6 c3 c3 dc b1 a3 ce ca cc e2 00 c3 dc b1 a3 ce ca cc e2 00 d3 c9 d3 da c4 fa b3 a4 c6 da c3 bb d3 d0 d1 e9 d6 a4 c3 dc b1 a3 a3 ac ce aa c1 cb c8 b7 b1 a3 c4 fa b5 } //1
		$a_01_2 = {b5 e7 d0 c5 be c5 00 b5 e7 d0 c5 ca ae 00 b5 e7 d0 c5 ca ae d2 bb 00 cd f8 cd a8 ce e5 00 b5 e7 d0 c5 ca ae b6 fe 00 b5 e7 d0 c5 ca ae cb c4 00 b5 e7 d0 c5 ca ae c8 fd } //1
		$a_01_3 = {de ce b7 cf c8 b7 e6 00 b2 c3 be f6 d6 ae b5 d8 00 ba da c9 ab c3 b5 b9 e5 00 b0 b5 d3 b0 b5 ba 00 cb a1 c8 f0 c2 ea } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}