
rule Trojan_O97M_EncDoc_RH_MTB{
	meta:
		description = "Trojan:O97M/EncDoc.RH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6e 65 21 30 64 21 71 70 78 66 73 74 69 66 6d 6d 21 29 6f 66 78 2e 70 63 6b 66 64 75 21 54 7a 74 75 66 6e 2f 4f 66 75 2f 58 66 63 44 6d 6a 66 6f 75 2a 2f 45 70 78 6f 6d 70 62 65 47 6a 6d 66 29 28 69 75 75 71 3b 30 30 66 74 72 76 6a 6f 66 73 70 74 62 68 76 6a 6d 62 73 6d 66 73 6e 62 2f 64 70 6e 30 79 30 69 66 62 77 7a 2f 66 79 66 28 2d 25 66 6f 77 3b 42 71 71 45 62 75 62 2c 28 5d 4f 74 44 4c 42 2f 66 79 66 28 2a 3c 29 4f 66 78 2e 50 63 6b 66 64 75 21 2e 64 70 6e 21 54 69 66 6d 6d 2f 42 71 71 6d 6a 64 62 75 6a 70 6f 2a 2f 54 69 66 6d 6d 46 79 66 64 76 75 66 29 25 66 6f 77 3b 42 71 71 45 62 75 62 2c 28 5d 4f 74 44 4c 42 2f 66 79 66 28 2a } //01 00  dne!0d!qpxfstifmm!)ofx.pckfdu!Tztufn/Ofu/XfcDmjfou*/EpxompbeGjmf)(iuuq;00ftrvjofsptbhvjmbsmfsnb/dpn0y0ifbwz/fyf(-%fow;BqqEbub,(]OtDLB/fyf(*<)Ofx.Pckfdu!.dpn!Tifmm/Bqqmjdbujpo*/TifmmFyfdvuf)%fow;BqqEbub,(]OtDLB/fyf(*
		$a_03_1 = {53 68 65 6c 6c 20 28 90 02 5f 28 90 02 5f 2c 20 22 31 32 22 29 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}