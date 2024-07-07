
rule Virus_Win32_Virut_AA{
	meta:
		description = "Virus:Win32/Virut.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 27 00 00 00 53 b9 bf 0c 00 00 8b da 66 31 10 8d 14 13 86 d6 8d 40 02 e2 f3 5b c3 5d c3 } //1
		$a_01_1 = {0f 31 c3 b8 00 10 00 00 33 c9 eb 25 85 c0 75 08 cd 2c 85 c0 79 ed eb 0e 66 8c ca c1 e3 0a 78 e3 73 e1 38 fe 74 dd e8 d5 ff ff ff 91 e8 cf ff ff ff f7 d9 55 03 c1 8b 6c 24 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}