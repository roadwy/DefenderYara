
rule Ransom_Win32_Kitoles_AB_MTB{
	meta:
		description = "Ransom:Win32/Kitoles.AB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 2f 4d 45 53 53 41 47 45 5d 5b 4d 45 4c 54 5d 5b 54 41 53 4b 4e 41 4d 45 5d 73 79 73 65 6d 2e 65 78 65 5b 2f 54 41 53 4b 4e 41 4d 45 5d 5b 41 55 54 4f 45 58 45 43 5d 5b 4f 4e 43 45 45 4c 45 56 41 54 45 5d 5b 52 45 41 44 4d 45 5d } //00 00 
	condition:
		any of ($a_*)
 
}