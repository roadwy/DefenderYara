
rule Trojan_Win32_GhostRat_AGR_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.AGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {b3 1c a1 04 f0 43 00 ba 0f 00 00 00 23 d0 0f b6 92 c6 f9 43 00 0f b6 cb 88 14 0f c1 e8 04 4b 85 c0 } //3
		$a_03_1 = {6a 00 68 d4 cf 40 00 e8 ?? ?? ?? ?? 8b d8 85 db 74 3b 53 e8 ?? ?? ?? ?? 85 c0 74 31 68 ff 01 00 00 6a 00 6a 00 8d 44 24 14 50 e8 ?? ?? ?? ?? 8b d8 85 db } //2
		$a_01_2 = {50 00 72 00 69 00 6e 00 74 00 65 00 72 00 20 00 64 00 72 00 69 00 76 00 65 00 72 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //1 Printer driver software installation
		$a_01_3 = {57 00 49 00 4e 00 44 00 4f 00 57 00 53 00 5c 00 47 00 47 00 54 00 41 00 4c 00 4c 00 5c 00 47 00 47 00 54 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //4 WINDOWS\GGTALL\GGTupdate.exe
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*4) >=10
 
}