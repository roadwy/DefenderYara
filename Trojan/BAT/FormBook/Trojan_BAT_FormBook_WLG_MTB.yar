
rule Trojan_BAT_FormBook_WLG_MTB{
	meta:
		description = "Trojan:BAT/FormBook.WLG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 00 61 00 6d 00 62 00 77 00 65 00 73 00 74 00 6f 00 6e 00 2e 00 67 00 61 00 2f 00 67 00 2f 00 } //01 00  lambweston.ga/g/
		$a_01_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //01 00  powershell
		$a_01_2 = {53 00 74 00 61 00 72 00 74 00 2d 00 53 00 6c 00 65 00 65 00 70 00 20 00 2d 00 53 00 65 00 63 00 6f 00 6e 00 64 00 73 00 20 00 31 00 38 00 } //01 00  Start-Sleep -Seconds 18
		$a_01_3 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_5 = {57 65 62 52 65 71 75 65 73 74 } //01 00  WebRequest
		$a_01_6 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}