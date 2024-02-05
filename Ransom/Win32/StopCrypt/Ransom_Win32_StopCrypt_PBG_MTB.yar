
rule Ransom_Win32_StopCrypt_PBG_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {5d c3 c7 05 90 01 04 88 61 4d 00 c3 c7 05 90 01 04 88 61 4d 00 c3 c7 05 90 01 04 88 61 4d 00 c3 c7 05 90 01 04 88 61 4d 00 c3 c7 05 90 01 04 88 61 4d 00 c3 c7 05 90 01 04 88 61 4d 00 c3 90 00 } //00 00 
		$a_00_2 = {5d 04 00 00 d5 15 05 80 5c 26 } //00 00 
	condition:
		any of ($a_*)
 
}