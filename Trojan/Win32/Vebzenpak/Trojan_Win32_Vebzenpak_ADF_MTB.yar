
rule Trojan_Win32_Vebzenpak_ADF_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0c 00 05 00 00 "
		
	strings :
		$a_02_0 = {de 6f 84 00 c7 85 f8 ?? ?? ?? a0 87 7b 3c c7 85 fc ?? ?? ?? 06 5b 00 00 c7 85 48 ?? ?? ?? 54 b9 40 00 c7 85 40 ?? ?? ?? 08 00 00 00 8d 95 40 ?? ?? ?? 8d 8d 60 ?? ?? ?? e8 d6 40 ?? ?? 68 bc 13 00 00 8d 85 0c ?? ?? ?? 50 8d 85 50 ?? ?? ?? 50 dd 05 40 12 40 00 51 51 dd 1c 24 8d 85 10 ?? ?? ?? 50 68 95 f5 3a 00 8d 85 f8 ?? ?? ?? 50 } //10
		$a_80_1 = {54 49 50 4f 46 44 41 59 2e 54 58 54 } //TIPOFDAY.TXT  5
		$a_80_2 = {52 4f 42 55 53 54 45 52 } //ROBUSTER  4
		$a_80_3 = {53 54 41 52 54 50 55 4e 4b 54 45 54 } //STARTPUNKTET  4
		$a_80_4 = {54 41 4c 4b 57 4f 52 54 48 59 } //TALKWORTHY  4
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*4+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4) >=12
 
}