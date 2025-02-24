
rule Trojan_Win64_Lazy_HGP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.HGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 10 4c d7 08 4c 89 44 24 38 41 b9 20 00 00 00 4c 89 44 24 30 49 8b cc 66 0f 7e c8 f2 0f 11 44 24 60 f3 0f 7e 44 d7 10 ba 04 00 35 83 0f b7 c0 89 44 24 50 66 48 0f 7e c8 44 89 44 24 28 48 c1 e8 30 44 89 44 24 54 } //2
		$a_81_1 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 41 6d 61 74 65 72 61 73 75 } //1 System\CurrentControlSet\Services\Amaterasu
		$a_81_2 = {52 65 67 69 73 74 72 79 5c 4d 61 63 68 69 6e 65 5c 53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 41 6d 61 74 65 72 61 73 75 } //1 Registry\Machine\System\CurrentControlSet\Services\Amaterasu
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}