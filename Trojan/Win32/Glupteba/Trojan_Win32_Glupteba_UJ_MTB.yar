
rule Trojan_Win32_Glupteba_UJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.UJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {21 db 09 cb 31 17 43 81 c3 90 01 04 81 c7 90 01 04 89 cb 29 db 39 f7 75 90 01 01 21 db c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}