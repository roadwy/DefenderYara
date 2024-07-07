
rule TrojanSpy_Win32_QQpass_gen_A{
	meta:
		description = "TrojanSpy:Win32/QQpass.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {7c 7c 5b 5d 54 61 6f 69 73 74 20 50 72 69 65 73 } //2 ||[]Taoist Pries
		$a_01_1 = {5b 5d 5b 5d 5b 5d 5b 5b 5b 5d 5d 31 39 38 39 2e 60 31 31 } //2 [][][][[[]]1989.`11
		$a_01_2 = {5b 42 61 63 6b 73 70 61 63 65 5d 00 5b 54 41 42 5d 00 5b 45 4e 54 45 52 5d 00 5b 53 48 49 46 54 } //3 䉛捡獫慰散]呛䉁]䕛呎剅]卛䥈呆
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=7
 
}