
rule Trojan_Win32_Guloader_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {52 53 56 e8 00 00 00 00 5a 81 c2 90 01 02 00 00 8d 9a 90 01 02 00 00 6b f6 00 69 f6 90 01 04 81 c6 90 01 04 31 32 83 c2 04 39 da 72 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPQ_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 72 73 6f 6c 75 6d } //01 00  Dorsolum
		$a_01_1 = {4d 6f 64 73 74 61 6e 64 73 6f 72 67 61 6e 69 73 61 74 69 6f 6e 65 72 } //01 00  Modstandsorganisationer
		$a_01_2 = {41 66 6b 6c 69 6e 67 65 72 2e 54 69 64 } //01 00  Afklinger.Tid
		$a_01_3 = {41 73 74 72 6f 6d 65 64 61 2e 41 45 52 } //01 00  Astromeda.AER
		$a_01_4 = {41 64 6d 69 74 74 69 6e 67 5c 44 69 67 72 65 73 73 69 76 65 5c 53 74 61 6c 64 65 6e 2e 64 6c 6c } //01 00  Admitting\Digressive\Stalden.dll
		$a_01_5 = {50 72 65 69 6e 69 74 69 61 74 69 6f 6e 5c 55 6d 61 61 6c 65 6c 69 67 65 73 5c 45 61 72 6e 65 73 74 6c 79 38 36 } //01 00  Preinitiation\Umaaleliges\Earnestly86
		$a_01_6 = {46 6c 69 70 70 65 72 6d 61 73 6b 69 6e 65 73 5c 47 72 75 6e 64 73 6b 75 64 64 65 6e 65 2e 45 43 4f } //00 00  Flippermaskines\Grundskuddene.ECO
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPQ_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 72 00 6f 00 6e 00 62 00 75 00 73 00 68 00 2e 00 41 00 6e 00 74 00 } //01 00  Ironbush.Ant
		$a_01_1 = {54 00 65 00 6c 00 65 00 67 00 69 00 67 00 61 00 6e 00 74 00 2e 00 69 00 6e 00 69 00 } //01 00  Telegigant.ini
		$a_01_2 = {41 00 6e 00 6f 00 63 00 69 00 61 00 73 00 73 00 6f 00 63 00 69 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 46 00 75 00 69 00 } //01 00  Anociassociation.Fui
		$a_01_3 = {55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 63 00 6f 00 72 00 6f 00 61 00 } //01 00  Uninstall\coroa
		$a_01_4 = {74 00 61 00 70 00 65 00 74 00 65 00 72 00 6e 00 65 00 5c 00 44 00 6d 00 70 00 65 00 5c 00 55 00 6e 00 69 00 76 00 65 00 72 00 73 00 61 00 6c 00 69 00 73 00 65 00 72 00 73 00 } //00 00  tapeterne\Dmpe\Universalisers
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPQ_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 00 6f 00 74 00 6f 00 63 00 65 00 6c 00 6c 00 65 00 5c 00 55 00 6e 00 73 00 75 00 72 00 67 00 69 00 63 00 61 00 6c 00 6c 00 79 00 } //01 00  Fotocelle\Unsurgically
		$a_01_1 = {41 00 72 00 62 00 65 00 6a 00 64 00 73 00 6f 00 72 00 67 00 61 00 6e 00 69 00 73 00 65 00 72 00 69 00 6e 00 67 00 65 00 6e 00 73 00 31 00 31 00 35 00 2e 00 6c 00 6e 00 6b 00 } //01 00  Arbejdsorganiseringens115.lnk
		$a_01_2 = {41 00 6e 00 65 00 6e 00 63 00 65 00 70 00 68 00 61 00 6c 00 6f 00 75 00 73 00 2e 00 4e 00 6f 00 6e 00 } //01 00  Anencephalous.Non
		$a_01_3 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4f 00 75 00 74 00 70 00 72 00 6f 00 64 00 75 00 63 00 65 00 5c 00 57 00 69 00 65 00 6e 00 65 00 72 00 73 00 74 00 69 00 67 00 65 00 72 00 6e 00 65 00 73 00 5c 00 55 00 6e 00 77 00 69 00 73 00 74 00 66 00 75 00 6c 00 5c 00 46 00 6f 00 72 00 72 00 65 00 74 00 6e 00 69 00 6e 00 67 00 73 00 6d 00 73 00 73 00 69 00 67 00 } //00 00  Software\Outproduce\Wienerstigernes\Unwistful\Forretningsmssig
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Guloader_RPQ_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 66 31 0c 1f d8 e4 d8 d9 eb 29 } //00 00 
	condition:
		any of ($a_*)
 
}