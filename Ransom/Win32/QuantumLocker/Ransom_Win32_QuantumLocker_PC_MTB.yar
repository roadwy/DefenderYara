
rule Ransom_Win32_QuantumLocker_PC_MTB{
	meta:
		description = "Ransom:Win32/QuantumLocker.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 45 fc 0f b7 4d f8 3b c1 7d 29 ff 75 f4 e8 90 01 04 59 89 45 f4 0f b7 45 fc 8b 4d 08 0f b6 04 01 0f b6 4d f4 33 c1 0f b7 4d fc 8b 55 0c 88 04 0a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}