
rule Trojan_Win64_CobaltStrike_SPL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 64 61 74 61 5c 33 62 65 66 34 37 39 2e 74 6d 70 } //1 programdata\3bef479.tmp
		$a_01_1 = {52 65 6c 65 61 73 65 5c 53 65 74 75 70 45 6e 67 69 6e 65 2e 70 64 62 } //1 Release\SetupEngine.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_CobaltStrike_SPL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 05 e8 b1 02 00 8d 48 01 0f af c8 83 e1 01 74 7c 48 8b 85 50 01 00 00 48 8b 00 48 8b 8d f0 00 00 00 48 89 01 48 8b 85 50 01 00 00 48 8b 8d f0 00 00 00 48 8b 09 48 63 49 3c 48 03 08 48 8b 85 38 01 00 00 48 89 08 48 8b 85 38 01 00 00 48 8b 00 8b 50 50 48 83 ec 20 31 c9 41 b8 00 30 00 00 41 b9 04 00 00 00 ff 15 90 02 04 48 83 c4 20 48 8b 8d 60 01 00 00 48 89 01 48 8b 85 60 01 00 00 48 8b 00 48 89 45 50 e9 90 00 } //6
		$a_01_1 = {41 70 70 6c 65 62 61 69 64 75 67 6f 6f 67 6c 65 62 69 6e 67 63 73 64 6e 62 6f 6b 65 79 75 61 6e 68 65 6c 6c 6f 77 6f 72 6c 64 2e 63 6f 6d } //1 Applebaidugooglebingcsdnbokeyuanhelloworld.com
	condition:
		((#a_03_0  & 1)*6+(#a_01_1  & 1)*1) >=7
 
}