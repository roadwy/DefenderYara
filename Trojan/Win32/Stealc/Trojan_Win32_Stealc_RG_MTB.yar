
rule Trojan_Win32_Stealc_RG_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 4c 24 30 91 e9 d1 5b 83 c4 0c 69 ed 91 e9 d1 5b 83 c6 04 8b c1 c1 e8 18 33 c1 69 c0 91 e9 d1 5b 33 e8 89 44 24 24 83 ef 01 75 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Stealc_RG_MTB_2{
	meta:
		description = "Trojan:Win32/Stealc.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 64 59 76 4c 71 4f 72 53 71 79 6d 73 6d 6b 78 4d 47 65 68 70 } //1 adYvLqOrSqymsmkxMGehp
		$a_01_1 = {51 6c 64 6b 6a 59 5a 71 58 52 59 55 74 56 61 67 4d 62 50 49 7a 71 52 45 42 } //1 QldkjYZqXRYUtVagMbPIzqREB
		$a_01_2 = {6d 52 65 59 45 56 70 41 72 6c 61 57 76 74 77 50 74 41 68 65 70 65 68 6c 64 77 7a } //1 mReYEVpArlaWvtwPtAhepehldwz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}