
rule Trojan_Win64_CobaltstrikeWinGo_AX_MTB{
	meta:
		description = "Trojan:Win64/CobaltstrikeWinGo.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 ea 01 40 8a 3c 16 8a 04 11 40 30 c7 40 88 3c 13 48 f7 c2 07 00 00 00 75 e5 48 83 fa 00 74 2b 48 f7 c2 0f 00 00 00 74 b2 48 f7 c2 07 00 00 00 75 cd 48 83 ea 08 48 8b 3c 16 48 8b 04 11 48 31 c7 48 89 3c 13 48 83 fa 10 7d } //1
		$a_01_1 = {2f 47 6f 62 79 70 61 73 73 41 56 2d 73 68 65 6c 6c 63 6f 64 65 2d 6d 61 69 6e 2f } //1 /GobypassAV-shellcode-main/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}