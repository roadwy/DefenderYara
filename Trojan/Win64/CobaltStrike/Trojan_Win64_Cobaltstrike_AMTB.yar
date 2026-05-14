
rule Trojan_Win64_Cobaltstrike_AMTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f 20 64 41 63 42 41 6c 6f 59 68 4b 6c 53 4a 41 77 3e } //cmd.exe /c echo dAcBAloYhKlSJAw>  1
		$a_80_1 = {45 61 73 74 6f 6e 48 61 6d 6d 65 73 } //EastonHammes  1
		$a_80_2 = {4e 61 70 6f 6c 65 6f 6e 46 75 6e 6b } //NapoleonFunk  1
		$a_80_3 = {4d 61 72 69 65 6c 61 53 63 68 75 73 74 65 72 } //MarielaSchuster  1
		$a_80_4 = {53 61 6d 44 6f 6f 6c 65 79 } //SamDooley  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}