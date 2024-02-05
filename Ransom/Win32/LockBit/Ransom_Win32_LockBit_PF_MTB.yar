
rule Ransom_Win32_LockBit_PF_MTB{
	meta:
		description = "Ransom:Win32/LockBit.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be c0 83 e8 0d 88 44 0c 90 01 01 41 83 f9 0c 72 90 00 } //01 00 
		$a_03_1 = {83 f0 6c 33 d2 88 44 24 90 01 01 8a 44 24 90 01 01 8a 44 14 90 01 01 8b 4c 24 90 01 01 02 ca 0f be c0 33 c8 88 4c 14 90 01 01 42 83 fa 0b 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}