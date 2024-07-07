
rule Trojan_Win32_Oailyt_A{
	meta:
		description = "Trojan:Win32/Oailyt.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f 54 44 6f 77 6e 46 69 6c 65 54 68 72 65 61 64 8b c0 55 8b ec 51 } //1
		$a_01_1 = {20 bf aa bb fa ca b1 bc e4 3a 20 00 ff ff ff ff 07 00 00 00 20 b3 a7 c9 cc a3 ba 00 ff ff ff ff 03 00 00 00 3c 44 3e 00 ff ff ff ff 07 00 00 00 56 69 70 31 2e 35 32 00 } //1
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}