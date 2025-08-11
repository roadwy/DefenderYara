
rule Trojan_Win32_ClickFix_EEN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.EEN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 03 00 00 "
		
	strings :
		$a_00_0 = {5b 00 53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 49 00 4f 00 2e 00 50 00 61 00 74 00 68 00 5d 00 3a 00 3a 00 47 00 65 00 74 00 54 00 65 00 6d 00 70 00 46 00 69 00 6c 00 65 00 4e 00 61 00 6d 00 65 00 28 00 29 00 2b 00 27 00 } //100 [System.IO.Path]::GetTempFileName()+'
		$a_00_1 = {3b 00 20 00 26 00 20 00 24 00 } //10 ; & $
		$a_00_2 = {68 00 69 00 64 00 64 00 65 00 6e 00 } //10 hidden
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=110
 
}