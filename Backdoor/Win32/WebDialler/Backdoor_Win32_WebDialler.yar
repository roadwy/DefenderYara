
rule Backdoor_Win32_WebDialler{
	meta:
		description = "Backdoor:Win32/WebDialler,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 08 00 00 03 00 "
		
	strings :
		$a_01_0 = {70 6c 61 79 67 72 6f 75 6e 64 2e 63 6f 6d } //01 00  playground.com
		$a_01_1 = {42 41 44 78 54 49 43 4b 45 54 78 53 54 41 54 55 53 } //01 00  BADxTICKETxSTATUS
		$a_01_2 = {44 69 61 6c 65 72 49 63 6f 6e 45 76 65 6e 74 } //01 00  DialerIconEvent
		$a_01_3 = {36 34 2e 31 35 39 2e 39 31 2e 31 39 33 } //01 00  64.159.91.193
		$a_01_4 = {4f 62 74 61 69 6e 65 64 20 66 72 65 73 68 20 74 69 63 6b 65 74 3a 20 } //01 00  Obtained fresh ticket: 
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 57 65 62 44 69 61 6c 6c 65 72 } //01 00  SOFTWARE\WebDialler
		$a_01_6 = {74 65 65 6e 70 75 73 73 79 2e 61 6e 64 6c 6f 74 73 6d 6f 72 65 2e 63 6f 6d } //01 00  teenpussy.andlotsmore.com
		$a_01_7 = {6e 36 64 64 6c 61 61 70 70 6d 75 74 65 78 } //00 00  n6ddlaappmutex
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_WebDialler_2{
	meta:
		description = "Backdoor:Win32/WebDialler,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 03 00 "
		
	strings :
		$a_01_0 = {25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 2c 20 25 63 25 30 32 64 2e 25 30 32 64 20 70 65 72 20 6d 69 6e } //03 00  %02d:%02d:%02d, %c%02d.%02d per min
		$a_01_1 = {40 6d 6d 70 72 73 } //03 00  @mmprs
		$a_01_2 = {41 4f 4c 20 44 69 61 6c 2d 4f 6e 2d 44 65 6d 61 6e 64 20 66 65 61 74 75 72 65 } //01 00  AOL Dial-On-Demand feature
		$a_01_3 = {70 72 65 6d 69 75 6d } //02 00  premium
		$a_01_4 = {6d 65 6d 62 65 72 73 70 6c 61 79 67 72 6f 75 6e 64 2e 63 6f 6d 2f } //03 00  membersplayground.com/
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 57 65 62 44 69 61 6c 6c 65 72 } //03 00  SOFTWARE\WebDialler
		$a_01_6 = {53 4f 46 54 57 41 52 45 5c 53 69 6d 70 6c 65 44 65 6c 69 76 65 72 79 56 65 68 69 63 6c 65 } //00 00  SOFTWARE\SimpleDeliveryVehicle
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_WebDialler_3{
	meta:
		description = "Backdoor:Win32/WebDialler,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 07 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {42 65 69 20 42 65 6e 75 74 7a 75 6e 67 20 64 69 65 73 65 72 20 53 6f 66 74 77 61 72 65 20 77 69 72 64 20 49 68 72 20 4d 6f 64 65 6d 20 65 69 6e 65 20 30 31 39 30 20 28 44 65 75 74 73 63 68 6c 61 6e 64 29 2c } //01 00  Bei Benutzung dieser Software wird Ihr Modem eine 0190 (Deutschland),
		$a_01_1 = {52 61 73 45 6e 75 6d 43 6f 6e 6e 65 63 74 69 6f 6e 73 41 } //02 00  RasEnumConnectionsA
		$a_01_2 = {42 54 56 20 49 6e 64 75 73 74 72 69 65 73 } //03 00  BTV Industries
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 44 69 61 6c 6c 65 72 50 72 6f 67 72 61 6d 5c 25 73 } //02 00  SOFTWARE\DiallerProgram\%s
		$a_01_4 = {63 68 65 20 65 72 68 65 62 74 20 75 6e 64 20 65 73 20 6d 69 74 20 73 65 69 6e 65 72 20 47 65 6e 65 68 6d 69 67 75 6e 67 20 67 65 73 63 68 69 65 68 74 2c 20 77 65 6e 6e 20 65 72 20 64 75 72 63 68 20 64 65 6e } //00 00  che erhebt und es mit seiner Genehmigung geschieht, wenn er durch den
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_WebDialler_4{
	meta:
		description = "Backdoor:Win32/WebDialler,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 03 00 "
		
	strings :
		$a_01_0 = {52 61 73 44 69 61 6c } //05 00  RasDial
		$a_01_1 = {70 6c 61 79 67 72 6f 75 6e 64 2e 63 6f 6d } //03 00  playground.com
		$a_01_2 = {44 49 44 49 00 70 72 65 6d 69 75 6d 00 64 70 5f 00 40 6d 6d 70 72 73 00 } //03 00  䥄䥄瀀敲業浵搀彰䀀浭牰s
		$a_01_3 = {44 49 44 49 00 00 31 31 34 00 30 35 38 33 34 33 00 } //02 00 
		$a_01_4 = {68 74 74 70 3a 2f 2f 63 6f 6d 6d 75 6e 69 74 79 2e 64 65 72 62 69 7a 2e 63 6f 6d 2f } //01 00  http://community.derbiz.com/
		$a_01_5 = {61 6e 64 6c 6f 74 73 6d 6f 72 65 2e 63 6f 6d } //02 00  andlotsmore.com
		$a_00_6 = {73 75 72 66 79 61 2e 63 6f 6d } //01 00  surfya.com
		$a_01_7 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 79 70 61 79 6d 61 74 65 2e 63 6f 6d 2f 64 69 61 6c 65 72 70 6c 61 74 66 6f 72 6d 2f 74 6d 70 2e 68 74 6d } //01 00  http://www.mypaymate.com/dialerplatform/tmp.htm
		$a_01_8 = {31 39 34 2e 36 37 2e 38 37 2e 33 33 } //01 00  194.67.87.33
		$a_01_9 = {32 32 32 2e 32 2e 31 31 31 2e 35 35 } //01 00  222.2.111.55
		$a_01_10 = {41 53 44 50 4c 55 47 49 4e } //00 00  ASDPLUGIN
	condition:
		any of ($a_*)
 
}