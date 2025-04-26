
rule Ransom_Win32_Zudochka_G_MSR{
	meta:
		description = "Ransom:Win32/Zudochka.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec a1 04 c0 41 00 83 e0 1f 6a 20 59 2b c8 8b 45 08 d3 c8 33 05 04 c0 41 00 5d } //1
		$a_01_1 = {8b ec 81 ec 20 0a 00 00 a1 04 c0 41 00 33 c5 89 45 f8 53 } //1
		$a_01_2 = {4c 6f 63 6b 42 69 74 20 44 65 63 72 79 70 74 6f 72 20 31 2e 33 } //1 LockBit Decryptor 1.3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}