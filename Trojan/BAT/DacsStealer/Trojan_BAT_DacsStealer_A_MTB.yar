
rule Trojan_BAT_DacsStealer_A_MTB{
	meta:
		description = "Trojan:BAT/DacsStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 00 48 00 5a 00 58 00 51 00 74 00 56 00 32 00 31 00 70 00 54 00 32 00 4a 00 71 00 5a 00 57 00 4e 00 30 00 49 00 43 00 41 00 69 00 56 00 32 00 6c 00 75 00 4d 00 7a 00 4a 00 66 00 56 00 6d 00 6c 00 6b 00 5a 00 57 00 39 00 44 00 62 00 32 00 35 00 30 00 63 00 6d 00 39 00 73 00 62 00 47 00 56 00 79 00 49 00 69 00 42 00 38 00 49 00 46 00 4e 00 6c 00 } //02 00  hHZXQtV21pT2JqZWN0ICAiV2luMzJfVmlkZW9Db250cm9sbGVyIiB8IFNl
		$a_01_1 = {62 00 47 00 56 00 6a 00 64 00 43 00 31 00 50 00 59 00 6d 00 70 00 6c 00 59 00 33 00 51 00 67 00 49 00 6b 00 46 00 6b 00 59 00 58 00 42 00 30 00 5a 00 58 00 4a 00 45 00 51 00 55 00 4e 00 55 00 65 00 58 00 42 00 6c 00 49 00 69 00 6b 00 67 00 66 00 43 00 42 00 50 00 64 00 58 00 51 00 74 00 55 00 33 00 52 00 79 00 61 00 57 00 35 00 6e 00 } //02 00  bGVjdC1PYmplY3QgIkFkYXB0ZXJEQUNUeXBlIikgfCBPdXQtU3RyaW5n
		$a_01_2 = {44 00 30 00 6f 00 52 00 32 00 56 00 30 00 4c 00 56 00 64 00 74 00 61 00 55 00 39 00 69 00 61 00 6d 00 56 00 6a 00 64 00 43 00 41 00 67 00 49 00 6c 00 64 00 70 00 62 00 6a 00 4d 00 79 00 58 00 30 00 52 00 70 00 63 00 32 00 74 00 45 00 63 00 6d 00 6c 00 32 00 5a 00 53 00 49 00 67 00 66 00 43 00 42 00 54 00 5a 00 57 00 78 00 6c 00 59 00 33 00 51 00 74 00 } //02 00  D0oR2V0LVdtaU9iamVjdCAgIldpbjMyX0Rpc2tEcml2ZSIgfCBTZWxlY3Qt
		$a_01_3 = {54 00 32 00 4a 00 71 00 5a 00 57 00 4e 00 30 00 49 00 43 00 41 00 69 00 55 00 32 00 56 00 79 00 61 00 57 00 46 00 73 00 54 00 6e 00 56 00 74 00 59 00 6d 00 56 00 79 00 49 00 6e 00 77 00 67 00 55 00 32 00 56 00 73 00 5a 00 57 00 4e 00 30 00 4c 00 55 00 39 00 69 00 61 00 6d 00 56 00 6a 00 64 00 43 00 41 00 74 00 52 00 6d 00 6c 00 79 00 63 00 33 00 51 00 } //02 00  T2JqZWN0ICAiU2VyaWFsTnVtYmVyInwgU2VsZWN0LU9iamVjdCAtRmlyc3Q
		$a_01_4 = {55 00 39 00 4b 00 43 00 68 00 48 00 5a 00 58 00 51 00 74 00 56 00 32 00 31 00 70 00 54 00 32 00 4a 00 71 00 5a 00 57 00 4e 00 30 00 49 00 43 00 4a 00 58 00 61 00 57 00 34 00 7a 00 4d 00 6c 00 39 00 44 00 59 00 57 00 4e 00 6f 00 5a 00 55 00 31 00 6c 00 62 00 57 00 39 00 79 00 65 00 53 00 49 00 67 00 66 00 43 00 42 00 54 00 5a 00 57 00 78 00 6c 00 59 00 33 00 51 00 74 00 } //02 00  U9KChHZXQtV21pT2JqZWN0ICJXaW4zMl9DYWNoZU1lbW9yeSIgfCBTZWxlY3Qt
		$a_01_5 = {54 00 32 00 4a 00 71 00 5a 00 57 00 4e 00 30 00 49 00 43 00 4a 00 77 00 64 00 58 00 4a 00 77 00 62 00 33 00 4e 00 6c 00 49 00 69 00 42 00 38 00 49 00 46 00 4e 00 6c 00 62 00 47 00 56 00 6a 00 64 00 43 00 31 00 50 00 59 00 6d 00 70 00 6c 00 59 00 33 00 51 00 67 00 4c 00 55 00 5a 00 70 00 63 00 6e 00 4e 00 } //00 00  T2JqZWN0ICJwdXJwb3NlIiB8IFNlbGVjdC1PYmplY3QgLUZpcnN
	condition:
		any of ($a_*)
 
}