
rule Trojan_BAT_Zusy_SPS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {42 6f 62 75 78 4d 61 6e 52 65 6d 61 73 74 65 72 65 64 2e 65 78 65 } //1 BobuxManRemastered.exe
		$a_81_1 = {72 69 67 68 74 20 63 6c 69 63 6b 69 6e 67 20 74 68 65 20 72 65 64 20 62 6f 78 20 77 6f 6e 27 74 20 73 61 76 65 20 79 6f 75 } //1 right clicking the red box won't save you
		$a_81_2 = {52 45 53 45 54 20 50 55 52 52 53 4f 4e 41 4c 20 43 4f 45 44 } //1 RESET PURRSONAL COED
		$a_81_3 = {59 6f 75 72 20 6d 6f 6e 65 79 3a } //1 Your money:
		$a_81_4 = {55 20 48 41 56 20 42 45 41 4e 20 48 41 4b 45 44 } //1 U HAV BEAN HAKED
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}