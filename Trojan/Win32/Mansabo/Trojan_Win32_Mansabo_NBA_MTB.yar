
rule Trojan_Win32_Mansabo_NBA_MTB{
	meta:
		description = "Trojan:Win32/Mansabo.NBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 48 71 4c 53 6c 69 7a 43 6c 78 6d 48 48 4d 53 4c 70 4a 47 55 53 48 79 54 67 65 46 6f 4f 7a 61 6c 68 4b 67 70 78 44 7a 6f 71 6a 77 45 54 6e 44 56 4a 79 79 51 41 58 6b 63 44 42 50 62 52 6d 6e 63 4a 61 46 70 61 77 } //2 fHqLSlizClxmHHMSLpJGUSHyTgeFoOzalhKgpxDzoqjwETnDVJyyQAXkcDBPbRmncJaFpaw
		$a_01_1 = {66 4a 68 6a 5a 42 7a 55 70 6b 76 7a 76 66 65 67 45 4b 62 58 58 4b 55 6a 6f 67 54 45 57 6e 6a 74 51 76 4a 46 4f 44 71 65 4a 59 45 59 63 71 52 50 } //1 fJhjZBzUpkvzvfegEKbXXKUjogTEWnjtQvJFODqeJYEYcqRP
		$a_01_2 = {6d 46 52 7a 73 65 6b 4a 70 6e 76 72 72 59 57 42 50 55 43 74 46 47 73 46 74 70 6c 52 75 48 4b 70 74 6e 6c 62 61 47 73 47 64 58 4c 54 7a 75 46 62 53 48 76 46 6d 61 48 42 } //1 mFRzsekJpnvrrYWBPUCtFGsFtplRuHKptnlbaGsGdXLTzuFbSHvFmaHB
		$a_01_3 = {51 44 76 44 4d 64 4f 70 76 6b 6d 78 4a 62 44 59 7a 4e 48 70 48 49 55 6c 4f 76 41 6b 4e 75 4e 4f 44 73 48 6a 71 66 48 65 77 72 4a 62 55 4d 6f 6f 74 53 63 52 4b } //1 QDvDMdOpvkmxJbDYzNHpHIUlOvAkNuNODsHjqfHewrJbUMootScRK
		$a_01_4 = {49 52 79 66 78 4b 6d 71 77 64 47 4d 58 4f 72 46 42 46 59 52 77 74 58 65 74 65 67 57 57 42 44 4c 61 64 72 4d 65 45 41 46 69 } //1 IRyfxKmqwdGMXOrFBFYRwtXetegWWBDLadrMeEAFi
		$a_01_5 = {62 74 69 6f 55 58 45 76 63 70 63 50 6c 44 51 58 70 72 77 59 4b 4c 6f 76 79 49 62 59 45 4c } //1 btioUXEvcpcPlDQXprwYKLovyIbYEL
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}