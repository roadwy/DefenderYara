
rule Trojan_Win32_Trickbot_ZD{
	meta:
		description = "Trojan:Win32/Trickbot.ZD,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 3a 5c 50 72 6f 6a 65 63 74 73 5c 57 65 62 49 6e 6a 65 63 74 5c 62 69 6e 5c 78 38 36 5c 52 65 6c 65 61 73 65 5f 6c 6f 67 67 65 64 5c 70 61 79 6c 6f 61 64 33 32 2e 70 64 62 } //2 F:\Projects\WebInject\bin\x86\Release_logged\payload32.pdb
		$a_01_1 = {50 61 79 6c 6f 61 64 20 28 62 75 69 6c 64 20 25 73 20 25 73 29 20 69 6e 6a 65 63 74 65 64 } //2 Payload (build %s %s) injected
		$a_01_2 = {c6 44 24 4c 44 53 c6 44 24 51 59 33 db c6 44 24 52 44 8b d3 8a 44 24 40 88 5c 24 53 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}