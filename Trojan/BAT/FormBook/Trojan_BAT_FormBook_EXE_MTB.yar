
rule Trojan_BAT_FormBook_EXE_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 02 8e 69 17 59 91 1f 70 61 0b } //01 00 
		$a_01_1 = {24 35 38 38 43 46 38 42 31 2d 36 31 35 37 2d 34 43 43 45 2d 39 42 32 36 2d 45 42 34 31 31 38 35 39 31 38 41 33 } //01 00  $588CF8B1-6157-4CCE-9B26-EB41185918A3
		$a_01_2 = {4e 61 74 69 76 65 56 61 72 69 61 6e 74 2e 64 6c 6c } //00 00  NativeVariant.dll
	condition:
		any of ($a_*)
 
}