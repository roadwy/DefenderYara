
rule Virus_Win32_Toobin_A{
	meta:
		description = "Virus:Win32/Toobin.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {e8 ff ff ff ff c0 5e 83 c6 32 8b fe ad 6a 04 59 c1 c0 08 3c 30 73 05 2c 43 c0 e8 02 04 04 3c 3f 76 08 2c 45 3c 19 76 02 2c 06 0f ac c2 06 e2 e0 92 0f c8 ab 4f 80 3e 20 75 d2 53 8b 43 0c 8b 70 0c ad 96 ad 8b 58 18 e8 b8 06 00 00 6c 4a ea 14 ee b9 84 82 a2 4a } //00 00 
	condition:
		any of ($a_*)
 
}