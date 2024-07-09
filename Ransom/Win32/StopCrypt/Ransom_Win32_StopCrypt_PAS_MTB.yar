
rule Ransom_Win32_StopCrypt_PAS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {8a 08 88 0a c3 } //1
		$a_00_1 = {cc cc cc cc cc cc cc cc cc cc cc 33 c9 c7 40 18 0f 00 00 00 89 48 14 88 48 04 c3 } //1
		$a_03_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c ?? ?? 30 04 31 81 ff ?? ?? ?? ?? 75 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*3) >=5
 
}