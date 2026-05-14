
rule Trojan_Win64_ShellcodeRunner_PAB_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 45 18 a4 94 42 1b c7 45 1c 8f bd 39 bc c7 45 20 bc e5 d1 7e c7 45 24 ae 38 c4 49 c7 45 28 3e 94 26 b4 c7 45 2c 78 c1 e2 ef c7 45 30 c0 b2 35 4a c7 45 34 13 e0 18 2d c7 45 38 4d 9c c6 0e c7 45 3c e2 ca 2e ef c7 45 40 3e 5e 2a b0 c7 45 44 76 c8 02 02 48 8d 4c 24 30 [0-ff] 41 b8 40 00 00 00 ff 15 e8 1c 00 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}