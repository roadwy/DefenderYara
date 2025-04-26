
rule TrojanProxy_Win32_Wintecor_A{
	meta:
		description = "TrojanProxy:Win32/Wintecor.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {83 fb 05 72 ?? 8b cb 8b 14 24 8b c5 e8 ?? ?? ff ff 8b c5 8b d0 03 d3 c6 02 e9 2b f0 2b f3 83 ee 05 42 89 32 } //3
		$a_01_1 = {5b 43 63 5d 6f 6e 74 65 6e 74 2d 5b 54 74 5d 79 70 65 3a 5b 5e } //1 [Cc]ontent-[Tt]ype:[^
		$a_03_2 = {4c 6f 63 61 74 69 6f 6e 3a 20 68 74 74 70 3a 2f 2f [0-10] 2f 61 76 69 72 2f 72 65 64 69 72 2e 70 68 70 3f } //1
		$a_01_3 = {48 54 54 50 2f 31 5b 2e 5d 5b 31 30 78 5d 20 28 5b 31 2d 35 5d 5b 30 2d 39 5d 5b 30 2d 39 5d 29 5b 5e } //1 HTTP/1[.][10x] ([1-5][0-9][0-9])[^
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}