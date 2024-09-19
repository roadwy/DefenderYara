
rule Trojan_Win32_CobaltStrike_AT_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.AT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 21 6d 01 35 65 0c 6f 66 65 0c 6f 66 65 0c 6f 66 b6 7e 6c 67 74 0c 6f 66 b6 7e 6a 67 c5 0c 6f 66 b6 7e 6b 67 72 0c 6f 66 71 73 6a 67 42 0c 6f 66 c1 72 6b 67 6a 0c 6f 66 c1 72 6c 67 7d 0c 6f 66 c1 72 6a 67 34 0c 6f 66 b6 7e 6e 67 60 0c 6f 66 65 0c 6e 66 e3 0c 6f 66 71 73 66 67 67 0c 6f 66 71 73 6f 67 64 0c 6f 66 71 73 90 66 64 0c 6f 66 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}