
rule Trojan_Win64_SelfDeleter_A{
	meta:
		description = "Trojan:Win64/SelfDeleter.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 83 ec 40 48 c7 c1 10 27 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 c1 48 8d 55 f8 e8 ?? ?? ?? ?? 48 8b 48 08 e8 ?? ?? ?? ?? 48 c7 c1 00 00 00 00 e8 } //1
		$a_03_1 = {8b 85 50 26 00 00 83 e8 02 39 85 98 26 00 00 ?? ?? 8b 85 50 26 00 00 83 e8 02 48 8b 95 40 26 00 00 48 98 c6 04 02 00 48 8b 95 40 26 00 00 48 8b 85 78 26 00 00 48 89 c1 e8 } //-1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*-1) >=1
 
}