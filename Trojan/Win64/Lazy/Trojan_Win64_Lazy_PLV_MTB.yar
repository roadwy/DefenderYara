
rule Trojan_Win64_Lazy_PLV_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 f7 f1 3d ab 10 f6 8f 0f 83 ?? ?? ?? ?? 48 8b 4d a8 8b 05 ?? ?? ?? ?? 31 d2 f7 35 7e 22 16 00 ba c0 cd 97 78 81 f2 43 ee 1d c9 09 d0 2d 17 c5 ec 6f 05 35 a7 e7 86 ba ed ca 60 fd 81 f2 fa 0f 8c 92 01 d0 25 31 15 d6 b4 48 83 f9 00 0f 94 c1 88 4d a7 3d 0e aa b9 ec 0f 83 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}