
rule Trojan_BAT_Tnega_RT_MTB{
	meta:
		description = "Trojan:BAT/Tnega.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 49 6e 74 65 72 6f 70 53 65 72 76 69 63 65 73 } //1 System.Runtime.InteropServices
		$a_01_1 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
		$a_01_2 = {53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //1 System.Resources
		$a_01_3 = {43 6f 77 73 41 6e 64 42 75 6c 6c 73 2e 47 61 6d 65 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 CowsAndBulls.GameForm.resources
		$a_01_4 = {43 6f 77 73 41 6e 64 42 75 6c 6c 73 2e 48 69 67 68 53 63 6f 72 65 73 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 CowsAndBulls.HighScoresForm.resources
		$a_01_5 = {43 6f 77 73 41 6e 64 42 75 6c 6c 73 2e 4d 61 69 6e 4d 65 6e 75 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 CowsAndBulls.MainMenuForm.resources
		$a_01_6 = {43 6f 77 73 41 6e 64 42 75 6c 6c 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CowsAndBulls.Properties.Resources.resources
		$a_01_7 = {34 43 38 31 36 39 35 32 42 41 35 33 43 43 33 36 31 44 38 45 34 35 42 44 38 33 33 33 33 38 44 43 36 34 32 37 45 34 41 35 44 35 46 30 36 45 42 41 44 35 33 35 31 46 44 34 36 34 33 39 41 31 35 41 } //5 4C816952BA53CC361D8E45BD833338DC6427E4A5D5F06EBAD5351FD46439A15A
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*5) >=12
 
}