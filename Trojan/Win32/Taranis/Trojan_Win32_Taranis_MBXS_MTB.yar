
rule Trojan_Win32_Taranis_MBXS_MTB{
	meta:
		description = "Trojan:Win32/Taranis.MBXS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 75 75 71 3b 30 30 7a 6e 2f 75 76 71 6a 62 6f 39 2f 64 6f 30 73 66 71 70 73 75 30 73 66 71 70 73 75 2f 71 69 71 } //1 iuuq;00zn/uvqjbo9/do0sfqpsu0sfqpsu/qiq
		$a_01_1 = {61 73 66 7b 6d 74 72 6a 33 6d 79 72 } //1 asf{mtrj3myr
		$a_01_2 = {60 6f 74 70 74 6a 65 6a 68 6a 65 6d 67 68 67 73 74 65 68 71 69 71 72 69 72 74 72 68 68 74 72 6e 6d 60 35 32 34 32 34 63 34 60 6e 75 79 69 76 7d 32 71 6d 72 32 6e 77 } //1 `otptjejhjemghgstehqiqrirtrhhtrnm`52424c4`nuyiv}2qmr2nw
		$a_01_3 = {61 00 38 00 3b 00 35 00 48 00 6d 00 77 00 74 00 72 00 6a 00 61 00 48 00 6d 00 77 00 74 00 72 00 6a 00 61 00 5a 00 78 00 6a 00 77 00 25 00 49 00 66 00 79 00 66 00 61 00 49 00 6a 00 6b 00 66 00 7a 00 71 00 79 00 } //1 a8;5HmwtrjaHmwtrjaZxjw%IfyfaIjkfzqy
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}