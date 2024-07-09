
rule Trojan_Win32_Fifesock_gen_C{
	meta:
		description = "Trojan:Win32/Fifesock.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 79 73 74 65 6d 73 6d 73 73 72 76 63 } //1 systemsmssrvc
		$a_01_1 = {69 6e 6a 65 63 74 2e 64 6c 6c 00 43 61 6c 63 48 61 73 68 00 } //1 湩敪瑣搮汬䌀污䡣獡h
		$a_01_2 = {4c 6f 6f 70 49 6e 6a 65 63 74 40 34 } //1 LoopInject@4
		$a_03_3 = {c7 44 24 10 40 00 00 00 c7 44 24 0c 00 30 00 00 b8 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 44 24 08 c7 44 24 04 00 00 00 00 8b 45 ec 89 04 24 a1 ?? ?? ?? ?? ff d0 } //1
		$a_01_4 = {eb 05 89 e2 0f 34 c3 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 b8 6c 00 00 00 e8 dd ff ff ff 83 c4 28 8d 80 4e 32 22 51 a3 } //1
		$a_01_5 = {66 83 38 00 74 19 8d 45 fc c1 00 07 8b 45 f8 0f b7 10 8d 45 fc 31 10 8d 45 f8 83 00 02 eb de 8b 45 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}