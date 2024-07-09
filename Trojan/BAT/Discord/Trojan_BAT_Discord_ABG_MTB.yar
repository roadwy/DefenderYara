
rule Trojan_BAT_Discord_ABG_MTB{
	meta:
		description = "Trojan:BAT/Discord.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {16 0a 05 2d 08 06 7e 63 ?? ?? 04 60 0a 05 6e 20 00 ?? ?? 80 6e 5f 2c 08 06 7e 64 ?? ?? 04 60 0a 02 04 61 03 04 61 5f 6e 20 00 ?? ?? 80 6e 5f 2c 08 } //2
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_3 = {43 72 65 61 74 65 44 65 6c 65 67 61 74 65 } //1 CreateDelegate
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_5 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //1 get_CurrentDomain
		$a_01_6 = {52 65 67 69 73 74 72 79 4b 65 79 } //1 RegistryKey
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}