
rule Backdoor_Win32_Dridex_SE_MTB{
	meta:
		description = "Backdoor:Win32/Dridex.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b c6 0f af c6 8d 3c 40 8b ce 0f af cf 8b c7 99 2b c2 8b 55 10 03 ca d1 f8 03 c1 8b 4d 08 8a 0c 0b 32 c8 85 d2 74 0b 8b 55 08 88 0c 13 8b 55 10 eb 06 8b 4d 08 88 0c 0b } //1
		$a_01_1 = {5c 62 61 67 5c 46 41 53 54 5c 74 72 61 6e 73 61 63 74 69 6f 6e 61 6c 5c 75 6e 70 6c 65 61 73 61 2e 70 64 62 } //1 \bag\FAST\transactional\unpleasa.pdb
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}