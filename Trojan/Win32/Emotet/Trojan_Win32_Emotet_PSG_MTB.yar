
rule Trojan_Win32_Emotet_PSG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 8d 0c 06 33 d2 8b c6 f7 75 ?? 8b 45 ?? 8a 04 50 30 01 46 3b 75 ?? 75 } //1
		$a_81_1 = {41 35 5a 6a 53 51 34 32 31 4e 33 74 6a 51 47 38 35 69 47 6a 45 6a 6c 53 6a 4f 51 4c 77 50 41 73 6d 4e 57 79 4f 52 61 78 70 32 31 36 36 } //1 A5ZjSQ421N3tjQG85iGjEjlSjOQLwPAsmNWyORaxp2166
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}