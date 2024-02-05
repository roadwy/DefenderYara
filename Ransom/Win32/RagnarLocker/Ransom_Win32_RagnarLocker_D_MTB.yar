
rule Ransom_Win32_RagnarLocker_D_MTB{
	meta:
		description = "Ransom:Win32/RagnarLocker.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 f0 8b 0c 0e 01 8c 05 90 01 04 8b 94 05 90 1b 00 8b ca c1 e9 90 01 01 88 4e ff 8b ca 88 94 05 90 01 04 83 c0 90 01 01 c1 e9 90 01 01 c1 ea 90 01 01 88 0e 88 56 01 83 f8 90 01 01 72 bd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}