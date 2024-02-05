
rule Trojan_Win64_Cobaltstrike_RE_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 83 f8 0d 49 63 c8 48 8b d3 4d 8d 49 01 48 0f 45 d0 48 03 4d d0 41 ff c0 0f b6 44 14 60 41 32 41 ff 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}