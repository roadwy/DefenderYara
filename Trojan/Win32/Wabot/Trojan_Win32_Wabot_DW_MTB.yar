
rule Trojan_Win32_Wabot_DW_MTB{
	meta:
		description = "Trojan:Win32/Wabot.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 75 49 43 7a 35 38 61 5d 28 21 21 2b 24 31 31 5b 26 6b 47 38 66 21 21 22 21 35 2a 38 2a 6d 26 75 22 3d 31 7c 25 21 22 3b 2e 3d 24 30 68 38 55 26 68 47 26 6e 69 3b 22 22 22 5e 74 54 32 2b 61 71 46 30 7d 24 71 31 5e 22 5e 3e 69 5d 66 56 5a 4f 6e 34 55 37 } //1 TuICz58a](!!+$11[&kG8f!!"!5*8*m&u"=1|%!";.=$0h8U&hG&ni;"""^tT2+aqF0}$q1^"^>i]fVZOn4U7
		$a_01_1 = {6c a3 6d 43 43 34 66 39 49 49 35 30 2a 66 7e 22 21 74 36 24 72 69 69 2a 6d 30 77 3c 22 3b 5f 43 59 6f 54 6d 54 2b 3d 6f 25 21 4a 5e 22 22 22 25 56 53 67 41 50 30 78 5a 75 6f 37 5e 3b 22 22 3b 29 65 6e 25 43 30 44 62 75 7b 68 25 5e 22 5c 6f 37 74 49 71 44 70 7a 73 54 74 5e } //1
		$a_01_2 = {76 35 5a 6d 39 72 2a 61 35 49 71 5a 26 5e 43 22 3c 65 56 30 2b 43 6b 5a 61 54 6c 2e 3b 3c 4c 72 79 30 34 61 73 39 74 31 33 3f 77 51 44 44 53 46 6f 72 6e 30 6e 3a 5e 2e 5e 5e 75 49 38 65 30 4a 74 78 47 4c 6d } //1 v5Zm9r*a5IqZ&^C"<eV0+CkZaTl.;<Lry04as9t13?wQDDSForn0n:^.^^uI8e0JtxGLm
		$a_01_3 = {5e 74 54 6e 74 3f 32 6d 4f 73 7a 7a 71 53 63 3a 5e 5e 21 68 6d 6b 36 5d 69 39 39 4f 6f 2e 3b 5f 58 62 2a 35 30 4c 78 64 30 31 3b 22 54 65 62 62 65 56 30 73 6d 44 } //1 ^tTnt?2mOszzqSc:^^!hmk6]i99Oo.;_Xb*50Lxd01;"TebbeV0smD
		$a_01_4 = {55 a3 32 61 57 78 73 44 46 2a 50 20 2e 20 2e 2e 21 65 50 44 51 44 51 46 44 4f 75 5d 2e 20 20 20 4f 49 6f 32 75 2b 75 54 34 34 37 2e 20 20 20 20 2e 21 73 50 57 64 6c 2b 37 6e 5b 49 61 2e 20 2e 29 47 57 57 67 4f a3 24 4c 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}