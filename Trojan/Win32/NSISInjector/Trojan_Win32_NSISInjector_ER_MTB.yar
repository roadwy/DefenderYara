
rule Trojan_Win32_NSISInjector_ER_MTB{
	meta:
		description = "Trojan:Win32/NSISInjector.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 65 6e 73 65 6c 65 73 73 6e 65 73 73 } //01 00  Tenselessness
		$a_01_1 = {42 61 6e 6b 62 65 73 74 79 72 65 6c 73 65 72 } //01 00  Bankbestyrelser
		$a_01_2 = {6d 65 6c 6c 65 6d 76 67 74 65 72 } //01 00  mellemvgter
		$a_01_3 = {42 00 75 00 69 00 6c 00 64 00 75 00 70 00 5c 00 53 00 6b 00 61 00 6c 00 64 00 65 00 64 00 65 00 73 00 } //01 00  Buildup\Skaldedes
		$a_01_4 = {75 00 73 00 65 00 72 00 2d 00 62 00 6f 00 6f 00 6b 00 6d 00 61 00 72 00 6b 00 73 00 2d 00 73 00 79 00 6d 00 62 00 6f 00 6c 00 69 00 63 00 2e 00 73 00 76 00 67 00 } //01 00  user-bookmarks-symbolic.svg
		$a_01_5 = {65 00 6d 00 62 00 6c 00 65 00 6d 00 2d 00 69 00 6d 00 70 00 6f 00 72 00 74 00 61 00 6e 00 74 00 2d 00 73 00 79 00 6d 00 62 00 6f 00 6c 00 69 00 63 00 2e 00 73 00 79 00 6d 00 62 00 6f 00 6c 00 69 00 63 00 2e 00 70 00 6e 00 67 00 } //00 00  emblem-important-symbolic.symbolic.png
	condition:
		any of ($a_*)
 
}