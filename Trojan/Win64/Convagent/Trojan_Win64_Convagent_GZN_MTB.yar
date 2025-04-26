
rule Trojan_Win64_Convagent_GZN_MTB{
	meta:
		description = "Trojan:Win64/Convagent.GZN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 8b f6 33 d2 b9 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b d8 48 83 f8 ?? ?? ?? c7 45 ?? 38 02 00 00 48 8d 55 ?? 48 8b c8 ff 15 } //4
		$a_03_1 = {48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75 } //2
		$a_01_2 = {64 61 74 61 5c 7a 63 72 78 64 65 62 75 67 2e 74 78 74 } //1 data\zcrxdebug.txt
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}