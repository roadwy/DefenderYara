
rule Trojan_Win32_Sfone_RE_MTB{
	meta:
		description = "Trojan:Win32/Sfone.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 53 4d 47 41 3b d3 34 4d d3 35 2f 29 23 1d 6b d3 34 4d 17 11 0b 05 ff e5 0b 4d d3 34 9d 03 f3 } //00 00 
	condition:
		any of ($a_*)
 
}