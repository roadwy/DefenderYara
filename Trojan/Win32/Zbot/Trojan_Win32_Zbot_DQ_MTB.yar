
rule Trojan_Win32_Zbot_DQ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DQ!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b4 4a 40 00 30 47 40 00 00 02 00 05 4b ff ff 00 19 28 58 ff 01 00 6b 10 00 e7 80 0c 00 0b b0 00 0c 00 31 78 ff 35 58 ff 00 2b 6c 0c 00 6b 10 00 e7 f5 01 00 00 00 28 58 ff 01 00 6b 14 00 e7 80 0c 00 0b b0 00 0c 00 23 54 ff 4f 00 00 2f 54 ff 35 58 ff 00 14 6c 0c 00 6b 14 00 e7 f5 01 00 00 00 6c 78 ff } //1
		$a_01_1 = {c7 40 ff 3e 4c ff fd c7 44 ff 0a c0 00 08 00 32 06 00 48 ff 44 ff 40 ff 00 28 04 4c ff 04 50 ff 10 04 07 1a 00 f5 07 00 00 00 80 0c 00 6c 4c ff 2a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}