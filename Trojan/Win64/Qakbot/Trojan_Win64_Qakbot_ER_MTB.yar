
rule Trojan_Win64_Qakbot_ER_MTB{
	meta:
		description = "Trojan:Win64/Qakbot.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 6f 75 4f 48 2e 64 6c 6c } //1 kouOH.dll
		$a_01_1 = {41 47 55 6b 66 5a 37 66 4b 35 } //1 AGUkfZ7fK5
		$a_01_2 = {42 51 32 79 6c 70 50 76 42 4f } //1 BQ2ylpPvBO
		$a_01_3 = {43 55 6d 54 36 4d 42 69 54 72 } //1 CUmT6MBiTr
		$a_01_4 = {44 42 71 4e 4f 33 68 52 58 71 } //1 DBqNO3hRXq
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}