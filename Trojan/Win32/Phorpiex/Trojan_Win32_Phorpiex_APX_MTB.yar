
rule Trojan_Win32_Phorpiex_APX_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.APX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 44 1d f0 30 04 3e 8d 45 f0 50 43 e8 ?? ?? ?? ?? 59 3b d8 72 ?? f6 14 3e 57 46 } //5
		$a_01_1 = {31 00 38 00 35 00 2e 00 32 00 31 00 35 00 2e 00 31 00 31 00 33 00 2e 00 36 00 36 00 } //3 185.215.113.66
		$a_03_2 = {8b ec 83 ec 10 56 57 be ?? ?? ?? ?? 8d 7d f0 a5 a5 a5 a5 8b 7d 08 57 33 f6 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2) >=10
 
}