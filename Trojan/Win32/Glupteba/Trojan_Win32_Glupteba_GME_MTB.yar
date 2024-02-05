
rule Trojan_Win32_Glupteba_GME_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 0e 09 ff 81 c6 90 01 04 89 c7 21 c0 39 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}