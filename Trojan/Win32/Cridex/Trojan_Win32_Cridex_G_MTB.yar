
rule Trojan_Win32_Cridex_G_MTB{
	meta:
		description = "Trojan:Win32/Cridex.G!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 68 6f 75 67 68 74 4f 66 66 5c 70 61 69 72 73 75 62 6a 65 63 74 5c 70 72 65 73 65 6e 74 45 71 75 61 74 65 5c 73 63 61 6c 65 50 75 74 73 6f 6f 6e 2e 70 64 62 } //1 ThoughtOff\pairsubject\presentEquate\scalePutsoon.pdb
		$a_01_1 = {0f af c2 0f b6 c0 69 d0 cb 00 00 00 0f b7 c7 0f b6 ca 2b c8 88 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}