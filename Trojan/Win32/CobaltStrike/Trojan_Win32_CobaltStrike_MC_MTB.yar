
rule Trojan_Win32_CobaltStrike_MC_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 40 20 33 86 ?? ?? ?? ?? 35 eb fa f5 ff 09 46 70 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 05 8b 4a 38 2b 4e 7c 03 c1 a3 ?? ?? ?? ?? 8b 82 3c 01 00 00 40 0f af 46 4c 89 46 4c 3b 3d ?? ?? ?? ?? 77 } //2
		$a_01_1 = {58 74 55 32 39 32 } //2 XtU292
		$a_01_2 = {54 6e 6c 74 38 38 37 62 79 33 } //2 Tnlt887by3
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}