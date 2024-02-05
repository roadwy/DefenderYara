
rule Ransom_Win32_Ranzylocker_AA_MTB{
	meta:
		description = "Ransom:Win32/Ranzylocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {30 1c 08 41 3b ca 72 90 0a 25 00 a1 90 01 04 33 c9 8b 55 90 01 01 89 45 90 01 01 85 d2 74 90 01 01 8b d8 83 7d 90 01 02 8d 45 90 01 01 0f 43 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}