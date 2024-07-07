
rule Trojan_Win32_Emotet_PEX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PEX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 14 31 0f b6 c0 03 c2 99 bf 90 01 04 f7 ff 8a 04 32 32 04 2b 88 03 90 00 } //1
		$a_81_1 = {4d 40 7e 4a 53 52 50 75 40 50 61 35 73 4d 3f 56 32 49 35 53 4c 64 44 64 52 57 78 71 78 48 69 71 7e 6e 36 38 6e 50 30 23 42 7e 56 30 4d 32 69 7a 77 36 3f 71 36 47 30 41 2a 32 4a 6a 78 41 71 74 7d 63 64 38 32 30 44 23 38 74 6b } //1 M@~JSRPu@Pa5sM?V2I5SLdDdRWxqxHiq~n68nP0#B~V0M2izw6?q6G0A*2JjxAqt}cd820D#8tk
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}