
rule Trojan_Win32_Glupteba_GMF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 ea 31 0a 81 c2 04 00 00 00 39 fa 90 01 02 c3 81 ee 90 01 04 89 f3 39 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}