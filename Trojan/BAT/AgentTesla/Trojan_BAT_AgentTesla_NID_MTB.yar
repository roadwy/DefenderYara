
rule Trojan_BAT_AgentTesla_NID_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 08 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 06 08 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d 28 ?? ?? ?? 0a 9c 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d 99 } //1
		$a_01_1 = {62 61 32 38 31 65 2d 33 61 39 39 2d 34 38 32 64 2d 39 62 30 34 2d 37 30 33 61 36 36 32 65 35 64 } //1 ba281e-3a99-482d-9b04-703a662e5d
		$a_01_2 = {4f 49 55 54 45 52 53 57 42 41 4a 48 47 46 46 44 53 41 46 48 4b 4f 49 4d 4e 59 48 47 54 54 52 46 47 44 52 43 46 45 53 45 57 44 } //1 OIUTERSWBAJHGFFDSAFHKOIMNYHGTTRFGDRCFESEWD
		$a_81_3 = {53 68 61 72 70 53 74 72 75 63 74 75 72 65 73 2e 53 6f 72 74 69 6e 67 2e 53 6f 72 74 48 65 6c 70 65 72 } //1 SharpStructures.Sorting.SortHelper
		$a_01_4 = {4d 79 57 65 62 65 53 6f 63 6b 65 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 MyWebeSocket.Properties.Resources.resources
		$a_01_5 = {50 4c 4f 4b 4e 4d 4a 49 55 48 42 56 47 59 54 46 43 58 44 52 45 53 5a 41 57 51 41 5a 41 44 46 47 46 54 46 47 59 43 54 59 59 54 52 44 45 58 47 } //1 PLOKNMJIUHBVGYTFCXDRESZAWQAZADFGFTFGYCTYYTRDEXG
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}