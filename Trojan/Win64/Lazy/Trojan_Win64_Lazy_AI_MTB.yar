
rule Trojan_Win64_Lazy_AI_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 2b 95 94 e8 07 39 bf 8e bc 44 5a 9d 8d 01 1d 82 5d 41 97 b0 95 b8 50 4e 91 d6 79 5a 95 25 f2 54 9e 08 f9 74 41 } //2
		$a_01_1 = {56 bf 7e c6 1d 0f f3 38 02 00 00 80 71 79 82 d1 6f 46 9d 05 79 f1 25 a1 b6 68 11 3e 4e 6e 8d 22 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}