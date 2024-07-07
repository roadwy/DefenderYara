
rule Trojan_BAT_CobaltStrike_AG_MSR{
	meta:
		description = "Trojan:BAT/CobaltStrike.AG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_80_0 = {55 77 42 6c 41 48 51 41 4c 51 42 54 41 48 51 41 63 67 42 70 41 47 4d 41 64 41 42 4e 41 47 38 41 5a 41 42 6c 41 43 41 41 4c 51 42 57 41 47 55 41 63 67 42 7a 41 47 6b 41 62 77 42 75 41 43 41 41 4d 67 41 4b 41 47 } //UwBlAHQALQBTAHQAcgBpAGMAdABNAG8AZABlACAALQBWAGUAcgBzAGkAbwBuACAAMgAKAG  2
		$a_80_1 = {64 41 42 79 41 48 6b 41 49 41 42 37 41 41 30 41 43 67 41 67 41 43 41 41 61 51 42 6d 41 43 41 41 4b 41 42 62 41 45 55 41 62 67 42 32 41 47 6b 41 63 67 42 76 41 47 34 41 62 51 42 6c 41 47 34 41 64 41 42 64 41 44 } //dAByAHkAIAB7AA0ACgAgACAAaQBmACAAKABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdAD  2
		$a_80_2 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //set_UseShellExecute  1
		$a_80_3 = {73 65 74 2d 69 74 65 6d 20 2d 70 61 74 68 20 22 66 75 6e 63 74 69 6f 6e 3a 67 6c 6f 62 61 6c 3a } //set-item -path "function:global:  1
		$a_80_4 = {41 62 6f 72 74 69 6e 67 2e 2e 2e } //Aborting...  1
		$a_80_5 = {24 78 3d 27 7b 30 7d 27 3b 24 79 3d 27 7b 31 7d 27 3b } //$x='{0}';$y='{1}';  1
		$a_80_6 = {2d 73 74 61 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 65 6e 63 6f 64 65 64 63 6f 6d 6d 61 6e 64 } //-sta -noprofile -executionpolicy bypass -encodedcommand  1
		$a_80_7 = {50 72 65 73 73 20 61 6e 79 20 6b 65 79 2e 2e 2e } //Press any key...  1
		$a_80_8 = {55 6e 61 62 6c 65 20 74 6f 20 6c 61 75 6e 63 68 20 61 70 70 6c 69 63 61 74 69 6f 6e 3a } //Unable to launch application:  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=11
 
}