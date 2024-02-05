
rule Trojan_Win32_FormBook_Y_MTB{
	meta:
		description = "Trojan:Win32/FormBook.Y!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 45 ff ff 75 f8 5a 30 02 ff 45 f8 49 75 } //00 00 
	condition:
		any of ($a_*)
 
}