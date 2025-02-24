
rule Trojan_Win32_Neoreblamy_NA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 74 0d ff 75 10 ff 75 0c ff 75 08 ff d0 5d c3 } //2
		$a_01_1 = {52 77 53 41 59 4d 55 6b 41 56 44 44 65 72 77 69 71 44 4c 50 6d 5a 54 70 6b 6b 79 79 } //1 RwSAYMUkAVDDerwiqDLPmZTpkkyy
		$a_01_2 = {67 69 79 70 42 58 53 73 6f 59 48 64 54 64 47 72 6c 56 58 47 5a 48 48 67 4f 62 4c 46 6d 79 } //1 giypBXSsoYHdTdGrlVXGZHHgObLFmy
		$a_01_3 = {7a 44 6d 4c 56 62 50 49 6a 52 70 53 4c 47 65 4f 58 6f 53 } //1 zDmLVbPIjRpSLGeOXoS
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}