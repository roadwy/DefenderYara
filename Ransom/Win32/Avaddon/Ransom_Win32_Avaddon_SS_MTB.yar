
rule Ransom_Win32_Avaddon_SS_MTB{
	meta:
		description = "Ransom:Win32/Avaddon.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 63 76 49 30 4d 76 61 7a 74 66 53 7a 64 62 45 73 65 47 68 70 37 49 3d } //01 00  ycvI0MvaztfSzdbEseGhp7I=
		$a_01_1 = {78 73 54 57 79 38 6e 4c 79 4e 66 53 7a 64 59 3d } //01 00  xsTWy8nLyNfSzdY=
		$a_01_2 = {77 50 4c 76 39 65 6a 67 35 41 3d 3d } //01 00  wPLv9ejg5A==
		$a_01_3 = {76 63 62 6b 39 75 76 6b 76 64 72 74 37 62 6e 47 35 50 62 72 35 41 3d 3d } //00 00  vcbk9uvkvdrt7bnG5Pbr5A==
	condition:
		any of ($a_*)
 
}