
rule Virus_Win32_Expiro_EM_bit{
	meta:
		description = "Virus:Win32/Expiro.EM!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 57 52 29 c0 83 c0 30 64 8b 38 51 8b 4f 08 89 f8 83 c0 0c 8b 10 83 c2 0c 8b 3a 53 8b d7 83 c2 18 8b 02 85 c0 0f 84 25 00 00 00 89 fa 83 c2 30 8b 12 8b 1a 81 e3 df 00 df 00 8b 52 0c c1 e2 08 01 da 81 ea 4b 33 45 32 85 d2 0f 84 09 00 00 00 } //1
		$a_03_1 = {8d 1a 8b 18 85 db 81 f3 ?? ?? ?? ?? 39 df 89 1f 8d 18 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}