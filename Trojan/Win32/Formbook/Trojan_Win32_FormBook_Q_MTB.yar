
rule Trojan_Win32_FormBook_Q_MTB{
	meta:
		description = "Trojan:Win32/FormBook.Q!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 1c 08 80 33 c7 41 4a 75 } //00 00 
	condition:
		any of ($a_*)
 
}