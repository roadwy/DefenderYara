
rule Trojan_Win32_Fareit_RT_MTB{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {81 f7 c7 bb ce 37 83 ff 6f 81 ff aa 00 00 00 9b db e3 66 0f 62 c8 dd c0 66 0f db e7 66 } //01 00 
		$a_03_1 = {89 3b 81 fe a3 00 00 00 3d fc 00 00 00 c7 44 24 90 01 01 9d 00 00 00 83 fa 62 66 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {79 54 48 49 41 46 5a 6b 77 4f 30 35 35 52 4e 62 49 70 38 78 4d 36 7a 51 64 31 35 35 } //01 00  yTHIAFZkwO055RNbIp8xM6zQd155
		$a_81_1 = {49 6e 74 65 72 76 61 6c 68 79 70 70 69 67 68 65 64 65 72 } //01 00  Intervalhyppigheder
		$a_81_2 = {53 6b 75 6c 64 65 72 62 6c 61 64 65 74 73 31 } //00 00  Skulderbladets1
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6d 65 6e 61 78 6b 65 77 65 72 61 6e 73 6b 78 6d 65 } //01 00  Rumenaxkeweranskxme
		$a_01_1 = {74 78 74 50 61 73 73 77 6f 72 64 } //01 00  txtPassword
		$a_01_2 = {77 61 6e 75 6d 65 73 66 72 73 63 73 61 73 66 76 32 } //01 00  wanumesfrscsasfv2
		$a_01_3 = {61 72 65 6e 61 6f 73 6b 75 6d 6e 66 73 65 73 } //00 00  arenaoskumnfses
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_4{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {36 2f 2f 2f 2f 36 2f 36 31 36 36 31 } //01 00  6////6/61661
		$a_81_1 = {50 72 6f 6c 6f 67 6b 6c 61 75 73 75 6c 65 6e 73 35 } //01 00  Prologklausulens5
		$a_81_2 = {46 6f 72 66 6c 79 74 74 65 6c 73 65 72 6e 65 73 37 } //01 00  Forflyttelsernes7
		$a_81_3 = {4d 69 6c 6a 62 65 73 6b 79 74 74 65 6c 73 65 73 72 65 67 6c 65 6d 65 6e 74 } //00 00  Miljbeskyttelsesreglement
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_5{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {48 4f 4f 4b 48 45 52 45 } //01 00  HOOKHERE
		$a_81_1 = {55 6e 72 65 67 69 73 74 65 72 48 6f 74 4b 65 79 } //01 00  UnregisterHotKey
		$a_81_2 = {55 6e 76 75 6c 67 61 72 69 7a 65 73 } //01 00  Unvulgarizes
		$a_81_3 = {4d 69 6c 6c 69 73 65 6b 75 6e 64 73 } //01 00  Millisekunds
		$a_81_4 = {42 4c 4f 4f 44 53 55 43 4b 49 4e 47 } //01 00  BLOODSUCKING
		$a_81_5 = {46 61 6b 65 65 72 73 } //01 00  Fakeers
		$a_81_6 = {42 61 6e 6b 64 69 72 65 6b 74 72 73 } //00 00  Bankdirektrs
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_6{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 69 73 6b 73 70 65 63 69 66 69 6b 61 74 69 6f 6e 65 6e 73 } //02 00  diskspecifikationens
		$a_01_1 = {52 65 70 72 73 65 6e 74 61 6e 74 73 6b 61 62 73 6d 64 65 74 73 38 } //01 00  Reprsentantskabsmdets8
		$a_01_2 = {66 6f 6c 6b 65 6b 6f 6d 65 64 69 65 72 6e 65 } //02 00  folkekomedierne
		$a_01_3 = {4b 6f 6e 63 65 6e 74 72 61 74 69 6f 6e 73 6c 65 6a 72 36 } //02 00  Koncentrationslejr6
		$a_01_4 = {53 74 72 75 6b 74 75 72 61 6c 69 73 74 65 6e 73 37 } //01 00  Strukturalistens7
		$a_01_5 = {42 65 72 65 67 6e 69 6e 67 73 65 6e 68 65 64 65 72 73 31 } //00 00  Beregningsenheders1
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_7{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {66 65 61 77 65 66 65 61 73 66 64 63 73 66 65 } //01 00  feawefeasfdcsfe
		$a_81_1 = {61 66 77 65 73 63 78 66 73 63 76 6b 66 65 61 73 6c 61 } //01 00  afwescxfscvkfeasla
		$a_81_2 = {43 45 61 45 6c 45 6c 45 57 45 69 45 6e 45 64 45 6f 45 77 45 50 45 72 45 6f 45 63 45 57 45 } //01 00  CEaElElEWEiEnEdEoEwEPErEoEcEWE
		$a_81_3 = {47 51 65 51 74 51 4d 51 6f 51 64 51 75 51 6c 51 65 51 48 51 61 51 6e 51 64 51 6c 51 65 51 57 51 } //01 00  GQeQtQMQoQdQuQlQeQHQaQnQdQlQeQWQ
		$a_81_4 = {43 37 72 37 79 37 70 37 74 37 44 37 65 37 63 37 72 37 79 37 70 37 74 37 } //01 00  C7r7y7p7t7D7e7c7r7y7p7t7
		$a_81_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  IsDebuggerPresent
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_8{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 6c 79 67 74 6e 69 6e 67 65 73 75 64 73 70 69 6c } //01 00  Flygtningesudspil
		$a_81_1 = {73 74 65 6e 6b 6e 75 73 65 72 65 6e 73 } //01 00  stenknuserens
		$a_81_2 = {41 6e 74 69 64 69 73 65 73 74 61 62 6c 69 73 68 6d 65 6e 74 61 72 69 61 6e 69 73 6d } //01 00  Antidisestablishmentarianism
		$a_81_3 = {55 4e 50 52 4f 56 49 44 45 44 4c 59 52 45 4b 4c 41 4d } //01 00  UNPROVIDEDLYREKLAM
		$a_81_4 = {41 6b 74 69 65 70 6f 73 74 65 72 6e 65 73 6a 61 67 65 72 69 65 72 6e 65 70 72 6f 35 } //01 00  Aktieposternesjageriernepro5
		$a_81_5 = {44 41 4e 53 4b 4c 52 45 52 46 4f 52 45 4e 49 4e } //01 00  DANSKLRERFORENIN
		$a_81_6 = {6d 61 67 69 73 74 72 61 74 73 72 65 67 65 72 69 6e 67 } //01 00  magistratsregering
		$a_81_7 = {46 6c 75 6f 72 73 6b 79 6c 64 6e 69 6e 67 65 72 73 32 } //01 00  Fluorskyldningers2
		$a_81_8 = {41 66 6d 72 6b 6e 69 6e 67 65 72 31 } //00 00  Afmrkninger1
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_9{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 00 35 00 7a 00 37 00 71 00 4b 00 79 00 42 00 57 00 43 00 58 00 77 00 31 00 61 00 67 00 30 00 42 00 42 00 43 00 63 00 77 00 77 00 33 00 77 00 53 00 48 00 33 00 35 00 45 00 62 00 6b 00 6e 00 48 00 42 00 4d 00 31 00 32 00 30 00 } //02 00  h5z7qKyBWCXw1ag0BBCcww3wSH35EbknHBM120
		$a_00_1 = {42 00 69 00 62 00 6c 00 69 00 6f 00 6d 00 61 00 6e 00 69 00 61 00 6e 00 69 00 73 00 6d 00 33 00 } //01 00  Bibliomanianism3
		$a_00_2 = {42 00 65 00 73 00 6b 00 72 00 69 00 76 00 65 00 6c 00 73 00 65 00 73 00 76 00 72 00 6b 00 74 00 6a 00 65 00 74 00 } //02 00  Beskrivelsesvrktjet
		$a_01_3 = {4b 65 66 6d 75 6e 61 65 64 73 66 78 65 63 73 64 73 } //02 00  Kefmunaedsfxecsds
		$a_01_4 = {65 75 69 73 66 64 6a 73 78 61 64 66 64 73 37 } //01 00  euisfdjsxadfds7
		$a_01_5 = {2b 62 57 4d 50 4c 69 62 43 74 6c } //00 00  +bWMPLibCtl
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Fareit_RT_MTB_10{
	meta:
		description = "Trojan:Win32/Fareit.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 6f 72 74 66 6f 72 70 61 67 74 6e 69 6e 67 65 72 6e 65 } //02 00  bortforpagtningerne
		$a_00_1 = {67 00 66 00 68 00 74 00 74 00 70 00 51 00 30 00 74 00 51 00 71 00 51 00 74 00 7a 00 69 00 65 00 78 00 55 00 52 00 31 00 57 00 45 00 33 00 76 00 43 00 78 00 57 00 75 00 58 00 57 00 47 00 43 00 4f 00 53 00 41 00 31 00 30 00 35 00 } //02 00  gfhttpQ0tQqQtziexUR1WE3vCxWuXWGCOSA105
		$a_00_2 = {6c 00 51 00 66 00 48 00 35 00 44 00 30 00 69 00 56 00 7a 00 63 00 30 00 61 00 58 00 58 00 68 00 34 00 6e 00 43 00 50 00 5a 00 31 00 43 00 65 00 54 00 70 00 31 00 39 00 33 00 } //02 00  lQfH5D0iVzc0aXXh4nCPZ1CeTp193
		$a_00_3 = {42 00 6f 00 65 00 4d 00 53 00 79 00 37 00 6f 00 41 00 36 00 4e 00 47 00 5a 00 66 00 71 00 4a 00 65 00 49 00 48 00 35 00 53 00 4f 00 77 00 79 00 55 00 4a 00 36 00 31 00 36 00 39 00 } //02 00  BoeMSy7oA6NGZfqJeIH5SOwyUJ6169
		$a_00_4 = {4b 00 6f 00 6e 00 64 00 65 00 6e 00 73 00 65 00 72 00 65 00 73 00 31 00 } //01 00  Kondenseres1
		$a_00_5 = {53 00 68 00 61 00 6b 00 65 00 73 00 70 00 65 00 61 00 72 00 65 00 61 00 6e 00 73 00 37 00 } //02 00  Shakespeareans7
		$a_01_6 = {6e 74 4d 55 4a 71 6c 6c 6b 70 61 53 61 45 66 } //02 00  ntMUJqllkpaSaEf
		$a_01_7 = {66 70 59 59 4b 4c 6d 76 48 6b 44 69 47 5a 6b 5a 56 50 } //01 00  fpYYKLmvHkDiGZkZVP
		$a_01_8 = {70 4c 59 6d 54 6c 51 62 42 70 6d 67 79 76 53 6f 4d } //00 00  pLYmTlQbBpmgyvSoM
	condition:
		any of ($a_*)
 
}