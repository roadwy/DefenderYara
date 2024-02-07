
rule Trojan_Win64_Qakbot_MA_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 6c 6c 6d 61 69 6e 36 34 2e 64 6c 6c } //02 00  dllmain64.dll
		$a_01_1 = {63 75 72 6c 20 68 74 74 70 3a 2f 2f 31 30 39 2e 31 37 32 2e 34 35 2e 39 2f 4c 65 71 2f } //02 00  curl http://109.172.45.9/Leq/
		$a_01_2 = {41 b9 10 00 00 00 4c 8d 05 de 1f 00 00 48 8d 15 dd 1f 00 00 31 c9 ff 15 5b 60 00 00 31 d2 48 8d 0d e6 1f 00 00 48 8b 1d 3b 60 00 00 ff d3 b9 98 3a 00 00 ff 15 26 60 00 00 48 8d 0d 0b 20 00 00 ba 01 00 00 00 ff d3 31 c9 } //00 00 
	condition:
		any of ($a_*)
 
}