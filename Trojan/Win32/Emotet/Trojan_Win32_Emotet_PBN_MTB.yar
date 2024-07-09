
rule Trojan_Win32_Emotet_PBN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b ea 8b 54 24 ?? 8a 14 10 32 14 2e 8b 6c 24 ?? 88 14 28 a1 ?? ?? ?? ?? 40 3b c3 a3 } //1
		$a_02_1 = {8a 14 01 8b 45 ?? 8b 08 8b 45 ?? 33 db 8a 1c 08 33 d3 8b 0d ?? ?? ?? ?? 8b 01 8b 4d ?? 88 14 01 } //1
		$a_81_2 = {62 78 34 71 63 49 54 4f 49 33 4d 5a 7b 79 71 51 46 34 35 23 67 23 24 3f 46 51 55 52 77 6d 52 4a 25 73 40 50 4f 63 40 63 4e 65 64 54 44 42 30 6c 42 66 6a 71 4e 70 31 74 48 7e 42 7e 75 64 71 76 6b 39 50 46 56 7b 7c 34 35 40 6a } //1 bx4qcITOI3MZ{yqQF45#g#$?FQURwmRJ%s@POc@cNedTDB0lBfjqNp1tH~B~udqvk9PFV{|45@j
		$a_81_3 = {25 46 7d 37 7e 52 39 52 64 63 4d 55 6b 41 63 7b 55 2a 4d 7a 63 6e 23 46 7e 55 7d 65 25 23 6e 56 46 77 75 7e 7a 69 6f 68 65 39 71 75 24 7d 23 70 79 4d 58 51 74 2a 50 45 31 2a 4d 49 73 44 } //1 %F}7~R9RdcMUkAc{U*Mzcn#F~U}e%#nVFwu~ziohe9qu$}#pyMXQt*PE1*MIsD
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=1
 
}