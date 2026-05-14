
rule Trojan_Win32_Phorpiex_APX_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 8b 4d 10 51 8b 55 0c 52 8b 45 08 50 68 ?? ?? ?? ?? 8d 8d 00 fe ff ff 51 ff 15 ?? ?? ?? ?? 83 c4 14 6a 00 6a 00 6a 00 6a 00 68 88 41 40 00 ff 15 } //2
		$a_01_1 = {31 37 38 2e 31 36 2e 35 34 2e 31 30 39 } //1 178.16.54.109
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Phorpiex_APX_MTB_2{
	meta:
		description = "Trojan:Win32/Phorpiex.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 8d 45 e8 50 ff 75 f8 8d 85 d0 e9 ff ff 50 ff 75 f0 ff 15 ?? ?? ?? ?? 8d 45 f8 50 68 ff 0f 00 00 8d 85 d0 e9 ff ff 50 ff 75 f4 } //1
		$a_01_1 = {31 00 37 00 38 00 2e 00 31 00 36 00 2e 00 35 00 34 00 2e 00 31 00 30 00 39 00 } //2 178.16.54.109
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}
rule Trojan_Win32_Phorpiex_APX_MTB_3{
	meta:
		description = "Trojan:Win32/Phorpiex.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 44 1d f0 30 04 3e 8d 45 f0 50 43 e8 ?? ?? ?? ?? 59 3b d8 72 ?? f6 14 3e 57 46 } //5
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 31 00 35 00 2e 00 31 00 31 00 33 00 2e 00 36 00 36 00 } //3 185.215.113.66
		$a_03_2 = {8b ec 83 ec 10 56 57 be ?? ?? ?? ?? 8d 7d f0 a5 a5 a5 a5 8b 7d 08 57 33 f6 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}