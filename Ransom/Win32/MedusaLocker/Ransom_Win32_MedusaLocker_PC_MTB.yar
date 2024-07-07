
rule Ransom_Win32_MedusaLocker_PC_MTB{
	meta:
		description = "Ransom:Win32/MedusaLocker.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 55 54 49 4e 48 55 49 4c 4f 31 33 33 37 } //1 PUTINHUILO1337
		$a_03_1 = {8b c6 8a 0c 31 33 d2 f7 75 90 01 01 8b 45 90 01 01 32 8a 90 01 04 88 0c 30 46 8b 4d 90 01 01 3b f7 72 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}