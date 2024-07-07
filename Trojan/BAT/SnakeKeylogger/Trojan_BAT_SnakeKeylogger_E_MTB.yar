
rule Trojan_BAT_SnakeKeylogger_E_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 4d 00 79 00 20 00 57 00 6f 00 72 00 6b 00 73 00 5c 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 53 00 74 00 75 00 64 00 69 00 6f 00 5c 00 4e 00 44 00 52 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 47 00 61 00 6d 00 65 00 73 00 5c 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 65 00 72 00 5c 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 5c 00 45 00 6e 00 76 00 69 00 72 00 6f 00 6e 00 6d 00 65 00 6e 00 74 00 73 00 5c 00 47 00 72 00 61 00 73 00 73 00 2e 00 70 00 6e 00 67 00 } //2 C:\My Works\Visual Studio\NDRWinFormGames\Platformer\Resources\Environments\Grass.png
		$a_01_1 = {47 00 72 00 6f 00 75 00 6e 00 64 00 2e 00 70 00 6e 00 67 00 } //2 Ground.png
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 73 } //1 GetMethods
		$a_01_4 = {53 00 6b 00 6f 00 63 00 6b 00 6f 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 Skocko.Properties.Resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=8
 
}