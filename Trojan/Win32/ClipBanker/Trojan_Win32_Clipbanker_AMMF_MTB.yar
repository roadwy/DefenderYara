
rule Trojan_Win32_Clipbanker_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 c1 88 45 17 66 0f 7e f0 32 c1 30 4d 36 88 45 27 48 8d 45 d8 49 ff c0 42 80 3c 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}