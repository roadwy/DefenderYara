
rule Ransom_Win32_Gansom_AB_MTB{
	meta:
		description = "Ransom:Win32/Gansom.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 70 6f 73 5c 72 61 6e 73 6f 6d 6c 6f 6c 5c 72 61 6e 73 6f 6d 6c 6f 6c 5c 6f 62 6a 5c 44 65 62 75 67 5c 72 61 6e 73 6f 6d 6c 6f 6c 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}