
rule Ransom_Win32_MedusaLocker_PB_MTB{
	meta:
		description = "Ransom:Win32/MedusaLocker.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 41 00 49 00 44 00 4d 00 45 00 4d 00 45 00 53 00 } //1 .SOFTWARE\PAIDMEMES
		$a_01_1 = {50 55 54 49 4e 48 55 49 4c 4f 31 33 33 37 } //1 PUTINHUILO1337
		$a_03_2 = {33 d2 8b c1 f7 75 ?? 8a 04 31 81 c2 ?? ?? ?? ?? 32 02 8b 55 ?? 88 04 11 41 8b 75 ?? 3b cf 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}