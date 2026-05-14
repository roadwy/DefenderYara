
rule Trojan_Win32_Guloader_RR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 30 30 ff 2f 2f 2f fe 30 30 30 ff 1d 49 76 ff 1a 4c 7d fe 2f 30 31 ff 2f 2f 2f fe 30 30 30 ff 2f 2f 2f fe 30 30 30 ee 2d 32 37 5c 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Guloader_RR_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 6e 64 65 72 66 6f 72 73 74 61 61 65 64 65 40 49 6e 6d 65 73 68 69 6e 67 2e 54 72 31 } //1 underforstaaede@Inmeshing.Tr1
		$a_01_1 = {45 66 74 65 72 6d 6c 65 74 31 23 30 21 } //1 Eftermlet1#0!
		$a_01_2 = {46 61 79 65 74 74 69 73 6d 20 4e 64 65 74 20 4c 65 76 61 6e 74 69 6e 65 72 20 31 } //1 Fayettism Ndet Levantiner 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Guloader_RR_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 6f 64 7a 6f 6c 69 63 20 53 75 6e 62 65 6c 74 73 20 73 74 69 63 6b 62 6f 61 74 20 31 } //1 Podzolic Sunbelts stickboat 1
		$a_01_1 = {53 6b 6e 64 73 65 6c 73 67 65 72 6e 69 6e 67 73 40 6a 75 73 73 69 76 65 73 2e 62 61 31 } //1 Skndselsgernings@jussives.ba1
		$a_01_2 = {48 65 6d 69 64 61 63 74 79 6c 6f 75 73 31 25 30 23 } //1 Hemidactylous1%0#
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Guloader_RR_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 69 6d 62 65 72 65 72 40 73 69 74 64 6f 77 6e 73 74 72 65 6a 6b 65 73 2e 46 6f 72 31 } //1 Limberer@sitdownstrejkes.For1
		$a_01_1 = {43 6f 70 61 72 63 65 6e 65 72 20 52 65 73 74 61 75 72 65 72 69 6e 67 73 61 72 62 65 6a 64 65 73 20 53 61 6d 6d 65 6e 68 66 74 6e 69 6e 67 73 20 31 } //1 Coparcener Restaureringsarbejdes Sammenhftnings 1
		$a_01_2 = {67 6f 6c 6c 75 62 31 39 30 37 } //1 gollub1907
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Guloader_RR_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 6c 79 64 65 6e 64 65 72 6e 65 40 48 65 6d 69 73 70 68 65 72 69 63 61 6c 33 36 2e 4e 6f 31 } //1 Forlydenderne@Hemispherical36.No1
		$a_01_1 = {44 65 74 61 6c 6a 65 70 72 6f 6a 65 6b 74 73 31 } //1 Detaljeprojekts1
		$a_01_2 = {25 42 72 61 69 6e 73 74 6f 72 6d 69 6e 67 65 72 6e 65 20 46 72 69 74 74 65 74 20 4d 6f 6e 61 72 63 68 69 73 6d 20 31 } //1 %Brainstormingerne Frittet Monarchism 1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Guloader_RR_MTB_6{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //1 SeShutdownPrivilege
		$a_81_1 = {49 6e 69 74 69 61 74 65 53 68 75 74 64 6f 77 6e 57 } //1 InitiateShutdownW
		$a_00_2 = {46 00 72 00 65 00 6e 00 61 00 74 00 61 00 65 00 20 00 42 00 69 00 6f 00 65 00 6e 00 65 00 72 00 67 00 69 00 20 00 52 00 65 00 63 00 68 00 61 00 62 00 69 00 74 00 69 00 73 00 6d 00 } //2 Frenatae Bioenergi Rechabitism
		$a_81_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_00_2  & 1)*2+(#a_81_3  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RR_MTB_7{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {70 6f 73 74 65 72 69 7a 65 5c 41 75 74 6f 6d 61 74 63 61 66 65 32 30 39 } //1 posterize\Automatcafe209
		$a_01_1 = {68 75 67 75 65 6e 6f 74 69 73 6d 5c 70 69 70 61 67 65 73 5c 6d 75 6c 69 67 67 6f 65 72 } //1 huguenotism\pipages\muliggoer
		$a_01_2 = {5c 6e 61 70 6f 6c 65 6f 6e 73 68 61 74 74 65 73 2e 67 69 66 } //1 \napoleonshattes.gif
		$a_01_3 = {72 75 6e 64 69 6e 67 65 72 73 5c 73 6f 6c 69 66 6c 75 63 74 69 6f 6e 61 6c 5c 54 61 75 74 6f 6c 6f 67 69 7a 65 72 } //1 rundingers\solifluctional\Tautologizer
		$a_01_4 = {4b 75 6e 73 74 75 64 73 74 69 6c 6c 69 6e 67 73 2e 54 72 69 } //1 Kunstudstillings.Tri
		$a_01_5 = {4d 65 6c 6c 65 6d 72 75 6d 73 74 61 6e 67 65 6e 74 65 72 6e 65 73 2e 63 68 72 } //1 Mellemrumstangenternes.chr
		$a_01_6 = {5c 52 65 6d 61 69 6e 65 73 5c 45 67 61 6c 65 5c 53 70 65 63 69 61 6c 76 73 6b 65 5c 46 72 69 61 62 6c 65 } //1 \Remaines\Egale\Specialvske\Friable
		$a_01_7 = {5c 52 65 6d 61 69 6e 65 73 5c 4b 75 6e 73 74 75 64 73 74 69 6c 6c 69 6e 67 73 2e 54 72 69 } //1 \Remaines\Kunstudstillings.Tri
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_Win32_Guloader_RR_MTB_8{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5c 70 6f 6c 79 61 6e 64 72 69 6f 75 73 2e 64 6c 6c } //1 \polyandrious.dll
		$a_01_1 = {6c 65 64 65 6c 73 65 73 6d 73 73 69 67 65 73 5c 71 75 69 6e 61 72 79 5c 70 6f 6e 63 68 6f 65 72 73 } //1 ledelsesmssiges\quinary\ponchoers
		$a_01_2 = {63 79 6b 65 6c 68 61 6e 64 6c 65 72 6e 65 73 } //1 cykelhandlernes
		$a_01_3 = {5c 70 61 6e 74 68 65 69 73 74 5c 66 65 6d 6f 67 74 79 76 65 61 61 72 73 6a 75 62 69 6c 75 6d 73 2e 69 6e 69 } //1 \pantheist\femogtyveaarsjubilums.ini
		$a_01_4 = {37 5c 61 61 62 65 6e 62 61 72 65 6c 73 65 6e 5c 73 61 6d 6c 65 6c 69 6e 73 65 72 6e 65 2e 67 69 66 } //1 7\aabenbarelsen\samlelinserne.gif
		$a_01_5 = {53 61 6e 6b 74 69 6f 6e 65 6e 5c 64 72 61 6d 61 74 75 72 67 65 72 73 } //1 Sanktionen\dramaturgers
		$a_01_6 = {63 3a 5c 4b 61 72 67 6f 65 6e 73 5c 6e 6f 72 74 68 6c 61 6e 64 5c 6d 65 6e 69 6e 67 73 6b 6f 72 72 65 6b 74 75 72 65 72 6e 65 73 2e 69 6e 69 } //1 c:\Kargoens\northland\meningskorrekturernes.ini
		$a_01_7 = {46 65 6d 6f 67 74 79 76 65 72 65 } //1 Femogtyvere
		$a_01_8 = {5c 6f 76 65 72 62 6c 69 6b 6b 65 6e 65 2e 74 78 74 } //1 \overblikkene.txt
		$a_01_9 = {54 79 6c 73 6b 6a 6f 6c 65 72 6e 65 2e 53 63 6c } //1 Tylskjolerne.Scl
		$a_01_10 = {5c 52 65 6d 6f 6e 73 74 72 61 6e 74 32 33 30 5c 6b 72 69 67 73 66 72 65 6c 73 65 72 6e 65 73 2e 65 78 65 } //1 \Remonstrant230\krigsfrelsernes.exe
		$a_01_11 = {65 6e 65 76 72 65 6c 73 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 74 6f 74 61 6c 73 79 73 74 65 6d 65 72 6e 65 73 5c 69 6d 6d 61 74 72 69 6b 75 6c 61 74 69 6f 6e 65 72 73 } //1 enevrelse\Uninstall\totalsystemernes\immatrikulationers
		$a_01_12 = {73 70 69 6c 6c 65 6b 6f 72 74 65 6e 65 73 5c 75 6e 68 75 6d 6f 72 6f 75 73 6e 65 73 73 5c 73 79 73 74 65 6d 75 64 76 69 6b 6c 69 6e 67 65 6e } //1 spillekortenes\unhumorousness\systemudviklingen
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}
rule Trojan_Win32_Guloader_RR_MTB_9{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 00 6e 00 74 00 65 00 72 00 6c 00 75 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 74 00 72 00 69 00 6d 00 65 00 74 00 68 00 79 00 6c 00 67 00 6c 00 79 00 63 00 69 00 6e 00 65 00 2e 00 65 00 78 00 65 00 } //1 interlucation trimethylglycine.exe
		$a_01_1 = {61 00 6e 00 6e 00 75 00 61 00 6c 00 73 00 20 00 75 00 64 00 6e 00 79 00 74 00 74 00 65 00 6c 00 69 00 67 00 74 00 20 00 67 00 61 00 72 00 61 00 6e 00 74 00 69 00 68 00 65 00 6e 00 73 00 74 00 74 00 65 00 6c 00 73 00 65 00 72 00 6e 00 65 00 } //1 annuals udnytteligt garantihensttelserne
		$a_01_2 = {61 00 6d 00 61 00 74 00 72 00 6f 00 72 00 6b 00 65 00 73 00 74 00 65 00 72 00 73 00 20 00 6f 00 75 00 74 00 72 00 61 00 6e 00 6b 00 } //1 amatrorkesters outrank
		$a_01_3 = {70 00 6a 00 75 00 73 00 6b 00 65 00 73 00 } //1 pjuskes
		$a_01_4 = {74 00 69 00 70 00 74 00 6f 00 70 00 70 00 69 00 73 00 68 00 } //1 tiptoppish
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RR_MTB_10{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 00 61 00 6b 00 74 00 75 00 72 00 61 00 64 00 61 00 74 00 6f 00 65 00 6e 00 20 00 75 00 6e 00 62 00 69 00 67 00 67 00 65 00 64 00 20 00 6d 00 61 00 6e 00 69 00 63 00 68 00 61 00 65 00 61 00 6e 00 69 00 7a 00 65 00 } //1 fakturadatoen unbigged manichaeanize
		$a_01_1 = {61 00 66 00 74 00 72 00 75 00 6b 00 6e 00 65 00 73 00 20 00 75 00 6e 00 66 00 65 00 61 00 74 00 68 00 65 00 72 00 20 00 72 00 65 00 73 00 75 00 6c 00 74 00 65 00 72 00 65 00 6e 00 64 00 65 00 73 00 } //1 aftruknes unfeather resulterendes
		$a_01_2 = {62 00 6c 00 74 00 65 00 6b 00 72 00 65 00 74 00 6a 00 65 00 72 00 6e 00 65 00 20 00 70 00 61 00 72 00 73 00 69 00 6d 00 6f 00 6e 00 79 00 2e 00 65 00 78 00 65 00 } //1 bltekretjerne parsimony.exe
		$a_01_3 = {62 00 65 00 73 00 6b 00 61 00 64 00 69 00 67 00 65 00 6c 00 73 00 65 00 72 00 } //1 beskadigelser
		$a_01_4 = {43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 4a 00 6f 00 68 00 6e 00 44 00 6f 00 65 00 5c 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 6c 00 69 00 6b 00 65 00 } //1 C:\Documents and Settings\JohnDoe\machinelike
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Guloader_RR_MTB_11{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 00 69 00 67 00 61 00 6e 00 74 00 69 00 73 00 6b 00 2e 00 74 00 78 00 74 00 } //1 Gigantisk.txt
		$a_01_1 = {5c 00 53 00 75 00 62 00 72 00 61 00 64 00 69 00 63 00 6e 00 65 00 73 00 73 00 31 00 33 00 35 00 } //1 \Subradicness135
		$a_01_2 = {6d 00 6f 00 6c 00 6c 00 79 00 68 00 61 00 77 00 6b 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 62 00 61 00 72 00 62 00 65 00 72 00 65 00 5c 00 4f 00 72 00 69 00 65 00 6e 00 74 00 61 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 6c 00 79 00 } //1 mollyhawk\Uninstall\barbere\Orientationally
		$a_01_3 = {5c 00 4c 00 65 00 6d 00 6d 00 65 00 73 00 36 00 37 00 5c 00 52 00 65 00 69 00 6d 00 70 00 6f 00 72 00 74 00 65 00 72 00 6e 00 65 00 2e 00 6a 00 70 00 67 00 } //1 \Lemmes67\Reimporterne.jpg
		$a_01_4 = {5c 00 75 00 64 00 68 00 75 00 67 00 67 00 65 00 6e 00 64 00 65 00 73 00 5c 00 55 00 64 00 62 00 72 00 65 00 6e 00 64 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 \udhuggendes\Udbrendes.exe
		$a_01_5 = {43 00 3a 00 5c 00 54 00 45 00 4d 00 50 00 5c 00 79 00 6f 00 67 00 69 00 73 00 5c 00 61 00 70 00 6f 00 74 00 65 00 6b 00 73 00 61 00 73 00 73 00 69 00 73 00 74 00 65 00 6e 00 74 00 65 00 72 00 6e 00 65 00 5c 00 46 00 61 00 6e 00 74 00 61 00 73 00 69 00 61 00 2e 00 6d 00 61 00 6c 00 } //1 C:\TEMP\yogis\apoteksassistenterne\Fantasia.mal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Guloader_RR_MTB_12{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {5c 00 54 00 72 00 61 00 6e 00 73 00 73 00 6b 00 72 00 69 00 62 00 65 00 72 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 } //1 \Transskriberingernes
		$a_01_1 = {76 00 69 00 73 00 65 00 72 00 69 00 6e 00 73 00 74 00 72 00 75 00 6d 00 65 00 6e 00 74 00 65 00 72 00 2e 00 65 00 66 00 66 00 } //1 viserinstrumenter.eff
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 73 00 70 00 72 00 6f 00 67 00 65 00 64 00 65 00 5c 00 61 00 74 00 6f 00 6d 00 6c 00 72 00 65 00 } //1 Software\Microsoft\Windows\CurrentVersion\sprogede\atomlre
		$a_01_3 = {5c 00 46 00 6c 00 6c 00 65 00 6e 00 5c 00 46 00 61 00 73 00 74 00 65 00 74 00 69 00 64 00 65 00 72 00 73 00 } //1 \Fllen\Fastetiders
		$a_01_4 = {5c 00 46 00 6c 00 6c 00 65 00 6e 00 5c 00 50 00 79 00 74 00 68 00 61 00 67 00 6f 00 72 00 65 00 61 00 6e 00 73 00 } //1 \Fllen\Pythagoreans
		$a_01_5 = {5c 00 74 00 75 00 72 00 6c 00 6f 00 75 00 67 00 68 00 5c 00 4e 00 6f 00 6e 00 66 00 61 00 6e 00 31 00 35 00 30 00 2e 00 64 00 6c 00 6c 00 } //1 \turlough\Nonfan150.dll
		$a_01_6 = {5c 00 54 00 72 00 69 00 62 00 75 00 74 00 74 00 65 00 6e 00 73 00 } //1 \Tributtens
		$a_01_7 = {74 00 61 00 6b 00 74 00 72 00 65 00 67 00 75 00 6c 00 65 00 72 00 65 00 6e 00 64 00 65 00 73 00 2e 00 62 00 6c 00 61 00 } //1 taktregulerendes.bla
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_Win32_Guloader_RR_MTB_13{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 00 68 00 6f 00 6c 00 6f 00 73 00 63 00 6f 00 70 00 79 00 5c 00 68 00 79 00 64 00 72 00 6f 00 6d 00 79 00 73 00 } //1 choloscopy\hydromys
		$a_01_1 = {5c 00 61 00 66 00 73 00 74 00 61 00 6b 00 5c 00 46 00 6f 00 72 00 65 00 73 00 70 00 65 00 61 00 6b 00 65 00 72 00 31 00 39 00 38 00 2e 00 67 00 69 00 66 00 } //1 \afstak\Forespeaker198.gif
		$a_01_2 = {5c 00 65 00 66 00 74 00 65 00 72 00 6d 00 72 00 6b 00 6e 00 65 00 5c 00 43 00 6f 00 6d 00 65 00 73 00 74 00 2e 00 69 00 6e 00 69 00 } //1 \eftermrkne\Comest.ini
		$a_01_3 = {5c 00 43 00 6f 00 6e 00 63 00 65 00 70 00 74 00 75 00 61 00 6c 00 69 00 73 00 65 00 73 00 5c 00 68 00 79 00 6d 00 65 00 74 00 74 00 69 00 63 00 2e 00 69 00 6e 00 69 00 } //1 \Conceptualises\hymettic.ini
		$a_01_4 = {74 00 72 00 65 00 73 00 61 00 61 00 72 00 73 00 66 00 64 00 73 00 65 00 6c 00 73 00 64 00 61 00 67 00 5c 00 6e 00 65 00 70 00 6f 00 74 00 69 00 73 00 6d 00 73 00 } //1 tresaarsfdselsdag\nepotisms
		$a_01_5 = {6c 00 73 00 65 00 66 00 72 00 64 00 69 00 67 00 68 00 65 00 64 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 6f 00 62 00 6a 00 65 00 63 00 74 00 69 00 7a 00 69 00 6e 00 67 00 5c 00 53 00 6e 00 6f 00 68 00 61 00 6c 00 65 00 72 00 6e 00 65 00 } //1 lsefrdighed\Uninstall\objectizing\Snohalerne
		$a_01_6 = {75 00 64 00 73 00 6b 00 72 00 69 00 66 00 74 00 73 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 } //1 udskriftsprograms
		$a_01_7 = {66 00 6f 00 72 00 62 00 72 00 75 00 67 00 65 00 72 00 61 00 64 00 72 00 65 00 73 00 73 00 65 00 72 00 5c 00 76 00 69 00 74 00 61 00 6c 00 69 00 74 00 65 00 74 00 65 00 72 00 73 00 } //1 forbrugeradresser\vitaliteters
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_Win32_Guloader_RR_MTB_14{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {70 00 73 00 65 00 75 00 64 00 6f 00 6d 00 6f 00 72 00 70 00 68 00 69 00 73 00 6d 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 75 00 64 00 62 00 79 00 67 00 6e 00 69 00 6e 00 67 00 73 00 70 00 6c 00 61 00 6e 00 73 00 5c 00 54 00 79 00 6b 00 70 00 61 00 6e 00 64 00 65 00 74 00 68 00 65 00 64 00 65 00 6e 00 } //1 pseudomorphism\Uninstall\udbygningsplans\Tykpandetheden
		$a_01_1 = {73 00 68 00 75 00 6e 00 74 00 6d 00 6f 00 64 00 73 00 74 00 61 00 6e 00 64 00 65 00 6e 00 65 00 } //1 shuntmodstandene
		$a_01_2 = {5c 00 6d 00 61 00 6e 00 64 00 69 00 62 00 75 00 6c 00 69 00 66 00 6f 00 72 00 6d 00 5c 00 74 00 61 00 73 00 74 00 61 00 74 00 75 00 72 00 65 00 72 00 2e 00 69 00 6e 00 69 00 } //1 \mandibuliform\tastaturer.ini
		$a_01_3 = {4b 00 75 00 6c 00 6d 00 69 00 6e 00 61 00 74 00 69 00 6f 00 6e 00 65 00 6e 00 33 00 32 00 5c 00 73 00 6f 00 6d 00 6d 00 65 00 72 00 68 00 75 00 73 00 6f 00 6d 00 72 00 61 00 61 00 64 00 65 00 72 00 6e 00 65 00 73 00 } //1 Kulminationen32\sommerhusomraadernes
		$a_01_4 = {25 00 50 00 6f 00 64 00 73 00 6f 00 6c 00 69 00 63 00 25 00 5c 00 62 00 65 00 72 00 6c 00 69 00 6e 00 65 00 73 00 5c 00 77 00 61 00 72 00 } //1 %Podsolic%\berlines\war
		$a_01_5 = {64 00 6f 00 62 00 62 00 65 00 6c 00 74 00 72 00 75 00 64 00 65 00 73 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 66 00 69 00 6e 00 64 00 79 00 72 00 6b 00 65 00 73 00 } //1 dobbeltrudes\Uninstall\findyrkes
		$a_01_6 = {72 00 65 00 73 00 70 00 69 00 72 00 61 00 74 00 6f 00 72 00 65 00 64 00 } //1 respiratored
		$a_01_7 = {52 00 61 00 64 00 69 00 6f 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 66 00 69 00 65 00 6e 00 73 00 2e 00 50 00 72 00 69 00 } //1 Radiotelegrafiens.Pri
		$a_01_8 = {62 00 61 00 6e 00 6b 00 65 00 74 00 74 00 65 00 6e 00 73 00 2e 00 66 00 6c 00 6c 00 } //1 bankettens.fll
		$a_01_9 = {64 00 69 00 61 00 62 00 6f 00 6c 00 61 00 72 00 63 00 68 00 79 00 2e 00 67 00 72 00 6f 00 } //1 diabolarchy.gro
		$a_01_10 = {75 00 64 00 72 00 61 00 61 00 62 00 73 00 6f 00 72 00 64 00 65 00 74 00 2e 00 73 00 6c 00 62 00 } //1 udraabsordet.slb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule Trojan_Win32_Guloader_RR_MTB_15{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 63 00 6c 00 6f 00 63 00 68 00 61 00 72 00 64 00 73 00 5c 00 70 00 72 00 69 00 6e 00 6b 00 2e 00 53 00 79 00 6e 00 } //1 \Application Data\clochards\prink.Syn
		$a_01_1 = {5c 00 4a 00 6f 00 68 00 6e 00 44 00 6f 00 65 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 75 00 64 00 62 00 65 00 64 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 \JohnDoe\Application Data\udbeder.dll
		$a_01_2 = {64 00 72 00 73 00 6c 00 67 00 65 00 72 00 65 00 6e 00 73 00 5c 00 73 00 6b 00 6f 00 76 00 67 00 61 00 6e 00 67 00 73 00 6d 00 6e 00 64 00 65 00 6e 00 65 00 73 00 } //1 drslgerens\skovgangsmndenes
		$a_01_3 = {5c 00 62 00 72 00 6e 00 65 00 68 00 61 00 76 00 65 00 70 00 64 00 61 00 67 00 6f 00 67 00 5c 00 69 00 6d 00 6d 00 75 00 6e 00 6f 00 63 00 68 00 65 00 6d 00 69 00 63 00 61 00 6c 00 2e 00 74 00 78 00 74 00 } //1 \brnehavepdagog\immunochemical.txt
		$a_01_4 = {5c 00 61 00 63 00 75 00 6d 00 69 00 6e 00 61 00 74 00 65 00 64 00 2e 00 69 00 6e 00 69 00 } //1 \acuminated.ini
		$a_01_5 = {62 00 61 00 63 00 6b 00 66 00 69 00 73 00 63 00 68 00 65 00 5c 00 6e 00 6f 00 6e 00 70 00 61 00 63 00 69 00 66 00 69 00 63 00 61 00 74 00 6f 00 72 00 79 00 5c 00 } //1 backfische\nonpacificatory\
		$a_01_6 = {5c 00 61 00 73 00 74 00 75 00 74 00 65 00 5c 00 73 00 75 00 62 00 6e 00 69 00 74 00 72 00 61 00 74 00 65 00 2e 00 74 00 78 00 74 00 } //1 \astute\subnitrate.txt
		$a_01_7 = {5c 00 70 00 6c 00 61 00 6e 00 6b 00 74 00 6f 00 6e 00 2e 00 7a 00 69 00 70 00 } //1 \plankton.zip
		$a_01_8 = {5c 00 75 00 6e 00 67 00 61 00 72 00 6e 00 73 00 6f 00 70 00 68 00 6f 00 6c 00 64 00 65 00 6e 00 65 00 2e 00 7a 00 69 00 70 00 } //1 \ungarnsopholdene.zip
		$a_01_9 = {67 00 65 00 73 00 74 00 75 00 73 00 73 00 65 00 72 00 6e 00 65 00 73 00 5c 00 50 00 6f 00 6c 00 69 00 74 00 69 00 6b 00 6b 00 65 00 72 00 6e 00 65 00 5c 00 70 00 61 00 61 00 70 00 61 00 73 00 73 00 65 00 6c 00 69 00 67 00 } //1 gestussernes\Politikkerne\paapasselig
		$a_01_10 = {5c 00 41 00 6e 00 66 00 72 00 61 00 63 00 74 00 31 00 38 00 35 00 5c 00 75 00 6e 00 65 00 76 00 61 00 73 00 69 00 76 00 65 00 6c 00 79 00 2e 00 65 00 78 00 65 00 } //1 \Anfract185\unevasively.exe
		$a_01_11 = {41 00 70 00 70 00 72 00 6f 00 6b 00 73 00 69 00 6d 00 61 00 74 00 69 00 76 00 65 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 74 00 75 00 61 00 72 00 65 00 67 00 69 00 73 00 6b 00 65 00 5c 00 41 00 74 00 6f 00 6e 00 69 00 63 00 69 00 74 00 79 00 34 00 30 00 } //1 Approksimative\Uninstall\tuaregiske\Atonicity40
		$a_01_12 = {25 00 73 00 75 00 70 00 65 00 72 00 61 00 74 00 74 00 61 00 69 00 6e 00 61 00 62 00 6c 00 65 00 6e 00 65 00 73 00 73 00 25 00 5c 00 46 00 6f 00 72 00 65 00 64 00 72 00 61 00 67 00 73 00 72 00 6b 00 6b 00 65 00 72 00 31 00 39 00 32 00 5c 00 61 00 6e 00 74 00 68 00 6f 00 6e 00 69 00 65 00 } //1 %superattainableness%\Foredragsrkker192\anthonie
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}