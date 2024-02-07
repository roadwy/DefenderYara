
rule Trojan_Win32_NSISInject_BT_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 78 6f 74 69 63 69 74 79 36 37 5c 74 79 72 61 6e 6e 69 73 65 72 69 6e 67 65 6e 73 2e 64 6c 6c } //01 00  Exoticity67\tyranniseringens.dll
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 72 69 6c 6c 65 72 6e 65 5c 65 78 61 67 67 65 72 61 74 69 76 65 6e 65 73 73 5c 62 65 6d 72 6b 65 6c 73 65 6e 73 } //01 00  Software\rillerne\exaggerativeness\bemrkelsens
		$a_01_2 = {66 6f 72 62 69 65 72 73 5c 73 61 66 74 6e 69 6e 67 65 72 6e 65 5c 75 6e 66 61 69 6c 61 62 6c 79 2e 69 6e 69 } //01 00  forbiers\saftningerne\unfailably.ini
		$a_01_3 = {73 68 6f 77 64 6f 77 6e 5c 63 75 6c 67 65 65 5c 4b 6f 6d 70 6c 69 6d 65 6e 74 32 35 31 5c 73 6b 75 62 62 65 72 65 6e 73 2e 64 6c 6c } //01 00  showdown\culgee\Kompliment251\skubberens.dll
		$a_01_4 = {52 65 66 75 6e 64 65 72 65 72 2e 75 6e 63 } //00 00  Refunderer.unc
	condition:
		any of ($a_*)
 
}