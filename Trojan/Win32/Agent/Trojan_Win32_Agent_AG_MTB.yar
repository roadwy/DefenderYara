
rule Trojan_Win32_Agent_AG_MTB{
	meta:
		description = "Trojan:Win32/Agent.AG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 e4 3b c7 73 77 8a 1c 18 80 f3 8f 8a c3 f6 d0 32 c3 24 0f 32 d8 8d 45 ef 88 5d ef 3b c1 73 34 3b f0 77 30 8b d8 2b de 3b ca 75 12 51 8d 4d d0 e8 } //01 00 
		$a_01_1 = {2e 00 74 00 6d 00 70 00 22 00 20 00 2d 00 2d 00 70 00 69 00 6e 00 67 00 } //01 00  .tmp" --ping
		$a_01_2 = {22 00 25 00 73 00 22 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 25 00 73 00 22 00 } //00 00  "%s" start "%s"
	condition:
		any of ($a_*)
 
}