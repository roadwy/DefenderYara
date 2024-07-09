
rule Trojan_Win32_Emotet_PSW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 30 55 } //1
		$a_81_1 = {36 53 78 57 57 6e 6e 5a 30 66 63 7a 71 76 68 70 64 34 31 7a 30 79 6e 37 62 66 42 43 68 54 57 4f 78 68 61 46 4b 68 64 56 45 78 37 5a 4b } //1 6SxWWnnZ0fczqvhpd41z0yn7bfBChTWOxhaFKhdVEx7ZK
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}